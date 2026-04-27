use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe handle to the `SQLite` database.
pub type DbPool = Arc<Mutex<Connection>>;

/// Open (or create) the `SQLite` database and run migrations.
pub fn init(path: &str) -> Result<DbPool> {
    let parent = Path::new(path).parent();
    if let Some(dir) = parent
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create db directory: {}", dir.display()))?;
    }

    let conn = Connection::open(path).with_context(|| format!("open sqlite db: {path}"))?;

    // WAL mode for better concurrent read performance.
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    // Verify database integrity on startup. Catches corruption from
    // unclean shutdowns or disk errors before we attempt migrations.
    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
        .with_context(|| "integrity_check query failed")?;
    if integrity != "ok" {
        anyhow::bail!("sqlite integrity_check failed: {integrity}");
    }

    migrate(&conn)?;

    Ok(Arc::new(Mutex::new(conn)))
}

fn migrate(conn: &Connection) -> Result<()> {
    // v1: core tables
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    NOT NULL UNIQUE,
            name        TEXT    NOT NULL,
            org         TEXT    NOT NULL,
            password    TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'pending_verification',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            verified_at TEXT,
            approved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS email_tokens (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            kind        TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            used        INTEGER NOT NULL DEFAULT 0
        );
        ",
    )
    .context("run db migrations v1")?;

    // v2: account tier and billing columns (safe to re-run on existing DBs)
    migrate_add_column(
        conn,
        "users",
        "tier",
        "TEXT NOT NULL DEFAULT 'observe_free'",
    )?;
    migrate_add_column(conn, "users", "stripe_customer_id", "TEXT")?;

    // v3: license keys for rg-feed-server authentication
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS license_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            key_value   TEXT    NOT NULL UNIQUE,
            label       TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'active',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            revoked_at  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_license_keys_user_id ON license_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_license_keys_key_value ON license_keys(key_value);
        ",
    )
    .context("run db migrations v3 (license_keys)")?;

    // v4: rename tier "observe_free" → "shadow" (S-1, v1.1.0).
    // SQLite has no ALTER COLUMN DEFAULT, but the column DEFAULT only applies
    // to INSERT without an explicit value. The Rust constant `tier::SHADOW`
    // is always supplied explicitly, so the old DEFAULT is harmless. We only
    // need to migrate existing rows.
    conn.execute(
        "UPDATE users SET tier = 'shadow' WHERE tier = 'observe_free'",
        [],
    )
    .context("run db migration v4 (tier rename observe_free → shadow)")?;

    Ok(())
}

/// Idempotent ALTER TABLE ADD COLUMN. `SQLite` returns "duplicate column name"
/// if the column already exists; we catch that and treat it as success.
/// NOTE: Uses format!() for DDL because column names cannot be parameterized.
/// All callers pass compile time string literals so there is no injection risk.
fn migrate_add_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    match conn.execute_batch(&sql) {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().contains("duplicate column name") => Ok(()),
        Err(e) => Err(e).with_context(|| format!("migrate add column {table}.{column}")),
    }
}

// ── User queries ────────────────────────────────────────────────

/// User status values. Stable strings — do not rename.
pub mod status {
    pub const PENDING_VERIFICATION: &str = "pending_verification";
    pub const PENDING_APPROVAL: &str = "pending_approval";
    pub const APPROVED: &str = "approved";
    pub const DENIED: &str = "denied";
}

/// Account tier values. Stable strings — do not rename.
#[allow(dead_code)] // Used in tests and future billing integration
pub mod tier {
    pub const SHADOW: &str = "shadow";
    pub const OBSERVE_PAID: &str = "observe_paid";
    pub const INLINE_LICENSED: &str = "inline_licensed";
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub org: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub status: String,
    pub tier: String,
    pub stripe_customer_id: Option<String>,
    pub created_at: String,
    pub verified_at: Option<String>,
    pub approved_at: Option<String>,
}

pub fn insert_user(
    conn: &Connection,
    email: &str,
    name: &str,
    org: &str,
    password_hash: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO users (email, name, org, password, tier) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![email, name, org, password_hash, tier::SHADOW],
    )
    .context("insert user")?;
    Ok(conn.last_insert_rowid())
}

pub fn get_user_by_email(conn: &Connection, email: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, email, name, org, password, status, tier, stripe_customer_id,
                created_at, verified_at, approved_at
         FROM users WHERE email = ?1",
    )?;

    let mut rows = stmt.query_map(rusqlite::params![email], row_to_user)?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn get_user_by_id(conn: &Connection, id: i64) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, email, name, org, password, status, tier, stripe_customer_id,
                created_at, verified_at, approved_at
         FROM users WHERE id = ?1",
    )?;

    let mut rows = stmt.query_map(rusqlite::params![id], row_to_user)?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

pub fn update_user_status(conn: &Connection, user_id: i64, new_status: &str) -> Result<()> {
    // Each branch uses a static SQL string to avoid format!() interpolation.
    match new_status {
        status::PENDING_APPROVAL => {
            conn.execute(
                "UPDATE users SET status = ?1, verified_at = datetime('now') WHERE id = ?2",
                rusqlite::params![new_status, user_id],
            )?;
        }
        status::APPROVED => {
            conn.execute(
                "UPDATE users SET status = ?1, approved_at = datetime('now') WHERE id = ?2",
                rusqlite::params![new_status, user_id],
            )?;
        }
        _ => {
            conn.execute(
                "UPDATE users SET status = ?1 WHERE id = ?2",
                rusqlite::params![new_status, user_id],
            )?;
        }
    }

    Ok(())
}

#[allow(dead_code)] // Future billing integration
pub fn update_user_tier(conn: &Connection, user_id: i64, new_tier: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET tier = ?1 WHERE id = ?2",
        rusqlite::params![new_tier, user_id],
    )
    .context("update user tier")?;
    Ok(())
}

#[allow(dead_code)] // Future billing integration
pub fn update_stripe_customer_id(conn: &Connection, user_id: i64, customer_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET stripe_customer_id = ?1 WHERE id = ?2",
        rusqlite::params![customer_id, user_id],
    )
    .context("update stripe customer id")?;
    Ok(())
}

pub fn update_password(conn: &Connection, user_id: i64, password_hash: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET password = ?1 WHERE id = ?2",
        rusqlite::params![password_hash, user_id],
    )
    .context("update password")?;
    Ok(())
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        name: row.get(2)?,
        org: row.get(3)?,
        password: row.get(4)?,
        status: row.get(5)?,
        tier: row.get(6)?,
        stripe_customer_id: row.get(7)?,
        created_at: row.get(8)?,
        verified_at: row.get(9)?,
        approved_at: row.get(10)?,
    })
}

// ── Email token queries ─────────────────────────────────────────

pub fn insert_email_token(conn: &Connection, token: &str, user_id: i64, kind: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO email_tokens (token, user_id, kind) VALUES (?1, ?2, ?3)",
        rusqlite::params![token, user_id, kind],
    )
    .context("insert email token")?;
    Ok(())
}

pub fn consume_email_token(
    conn: &Connection,
    token: &str,
    expected_kind: &str,
) -> Result<Option<i64>> {
    // Atomic consume: UPDATE with all conditions in WHERE, then read the affected row.
    // This eliminates the SELECT+UPDATE race where two concurrent callers could both
    // see used=0 and both proceed.
    conn.execute(
        "UPDATE email_tokens SET used = 1
         WHERE token = ?1 AND kind = ?2 AND used = 0
         AND datetime(created_at, '+7 days') > datetime('now')",
        rusqlite::params![token, expected_kind],
    )?;

    if conn.changes() == 0 {
        return Ok(None);
    }

    let user_id: i64 = conn.query_row(
        "SELECT user_id FROM email_tokens WHERE token = ?1",
        rusqlite::params![token],
        |row| row.get(0),
    )?;
    Ok(Some(user_id))
}

/// Consume an email token with a custom TTL (in hours). Used for password reset
/// tokens that expire sooner than the default 7 day window.
pub fn consume_email_token_ttl(
    conn: &Connection,
    token: &str,
    expected_kind: &str,
    ttl_hours: u32,
) -> Result<Option<i64>> {
    // Atomic consume with custom TTL. Same pattern as consume_email_token:
    // UPDATE first, then SELECT only if a row was changed.
    let modifier = format!("+{ttl_hours} hours");
    conn.execute(
        "UPDATE email_tokens SET used = 1
         WHERE token = ?1 AND kind = ?2 AND used = 0
         AND datetime(created_at, ?3) > datetime('now')",
        rusqlite::params![token, expected_kind, modifier],
    )?;

    if conn.changes() == 0 {
        return Ok(None);
    }

    let user_id: i64 = conn.query_row(
        "SELECT user_id FROM email_tokens WHERE token = ?1",
        rusqlite::params![token],
        |row| row.get(0),
    )?;
    Ok(Some(user_id))
}

// ── Session queries ─────────────────────────────────────────────

/// Insert a session using the SHA-256 hash of the token. The raw token is
/// never stored; only the hash is persisted. Callers must hash before storing.
pub fn insert_session(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    ttl_hours: u64,
) -> Result<()> {
    let modifier = format!("+{ttl_hours} hours");
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at)
         VALUES (?1, ?2, datetime('now', ?3))",
        rusqlite::params![token_hash, user_id, modifier],
    )
    .context("insert session")?;
    Ok(())
}

/// Validate a session by looking up the SHA-256 hash of the provided token.
pub fn validate_session(conn: &Connection, token_hash: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM sessions
         WHERE token = ?1 AND datetime(expires_at) > datetime('now')",
    )?;

    let user_id: Option<i64> = stmt
        .query_map(rusqlite::params![token_hash], |row| row.get(0))?
        .next()
        .and_then(Result::ok);

    Ok(user_id)
}

/// Delete a session by its token hash.
pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM sessions WHERE token = ?1",
        rusqlite::params![token_hash],
    )?;
    Ok(())
}

/// Delete all sessions for a user. Called after password reset to invalidate
/// any sessions an attacker may have obtained with the old credentials.
pub fn delete_sessions_for_user(conn: &Connection, user_id: i64) -> Result<usize> {
    let n = conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1",
        rusqlite::params![user_id],
    )?;
    Ok(n)
}

pub fn cleanup_expired_sessions(conn: &Connection) -> Result<usize> {
    let n = conn.execute(
        "DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')",
        [],
    )?;
    Ok(n)
}

/// Delete email tokens older than 30 days. Used tokens accumulate over time
/// and serve no purpose after their TTL window (7 days for verify/approve,
/// 1 hour for password reset). A 30 day retention provides ample margin.
pub fn cleanup_stale_email_tokens(conn: &Connection) -> Result<usize> {
    let n = conn.execute(
        "DELETE FROM email_tokens WHERE datetime(created_at, '+30 days') <= datetime('now')",
        [],
    )?;
    Ok(n)
}

// ── License key queries ─────────────────────────────────────────

/// License key status values. Stable strings — do not rename.
pub mod key_status {
    pub const ACTIVE: &str = "active";
    pub const REVOKED: &str = "revoked";
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LicenseKey {
    pub id: i64,
    pub user_id: i64,
    pub key_value: String,
    pub label: String,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Maximum number of active keys per user. Prevents abuse.
const MAX_ACTIVE_KEYS_PER_USER: usize = 5;

pub fn insert_license_key(
    conn: &Connection,
    user_id: i64,
    key_value: &str,
    label: &str,
) -> Result<i64> {
    // Enforce per-user key limit.
    let active_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM license_keys WHERE user_id = ?1 AND status = ?2",
        rusqlite::params![user_id, key_status::ACTIVE],
        |r| r.get(0),
    )?;

    let limit = i64::try_from(MAX_ACTIVE_KEYS_PER_USER).unwrap_or(5);
    if active_count >= limit {
        anyhow::bail!(
            "user {user_id} already has {active_count} active keys (limit {MAX_ACTIVE_KEYS_PER_USER})"
        );
    }

    conn.execute(
        "INSERT INTO license_keys (user_id, key_value, label) VALUES (?1, ?2, ?3)",
        rusqlite::params![user_id, key_value, label],
    )
    .context("insert license key")?;
    Ok(conn.last_insert_rowid())
}

pub fn get_license_keys_for_user(conn: &Connection, user_id: i64) -> Result<Vec<LicenseKey>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, key_value, label, status, created_at, revoked_at
         FROM license_keys WHERE user_id = ?1
         ORDER BY created_at DESC",
    )?;

    let rows = stmt.query_map(rusqlite::params![user_id], row_to_license_key)?;
    let mut keys = Vec::new();
    for row in rows {
        keys.push(row?);
    }
    Ok(keys)
}

/// Validate a license key. Returns the owning `user_id` if the key is active and
/// the user account is approved.
pub fn validate_license_key(conn: &Connection, key_value: &str) -> Result<Option<i64>> {
    let mut stmt = conn.prepare(
        "SELECT lk.user_id FROM license_keys lk
         JOIN users u ON lk.user_id = u.id
         WHERE lk.key_value = ?1 AND lk.status = ?2 AND u.status = ?3",
    )?;

    let user_id: Option<i64> = stmt
        .query_map(
            rusqlite::params![key_value, key_status::ACTIVE, status::APPROVED],
            |row| row.get(0),
        )?
        .next()
        .and_then(Result::ok);

    Ok(user_id)
}

pub fn revoke_license_key(conn: &Connection, key_id: i64, user_id: i64) -> Result<bool> {
    let n = conn.execute(
        "UPDATE license_keys SET status = ?1, revoked_at = datetime('now')
         WHERE id = ?2 AND user_id = ?3 AND status = ?4",
        rusqlite::params![key_status::REVOKED, key_id, user_id, key_status::ACTIVE],
    )?;
    Ok(n > 0)
}

fn row_to_license_key(row: &rusqlite::Row<'_>) -> rusqlite::Result<LicenseKey> {
    Ok(LicenseKey {
        id: row.get(0)?,
        user_id: row.get(1)?,
        key_value: row.get(2)?,
        label: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get(5)?,
        revoked_at: row.get(6)?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_db() -> DbPool {
        init(":memory:").expect("in-memory db")
    }

    #[test]
    fn schema_creates_tables() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        // Verify tables exist by querying sqlite_master.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','email_tokens','license_keys')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn insert_and_get_user() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let id = insert_user(&conn, "a@b.com", "Alice", "Acme Corp", "hash123").unwrap();
        assert!(id > 0);

        let user = get_user_by_email(&conn, "a@b.com").unwrap().unwrap();
        assert_eq!(user.name, "Alice");
        assert_eq!(user.org, "Acme Corp");
        assert_eq!(user.status, status::PENDING_VERIFICATION);
        assert_eq!(user.tier, tier::SHADOW);
        assert!(user.stripe_customer_id.is_none());
    }

    #[test]
    fn duplicate_email_rejected() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        insert_user(&conn, "a@b.com", "Alice", "Acme", "h").unwrap();
        let err = insert_user(&conn, "a@b.com", "Bob", "Other", "h");
        assert!(err.is_err());
    }

    #[test]
    fn status_transitions() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let id = insert_user(&conn, "a@b.com", "Alice", "Acme", "h").unwrap();

        update_user_status(&conn, id, status::PENDING_APPROVAL).unwrap();
        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.status, status::PENDING_APPROVAL);
        assert!(u.verified_at.is_some());

        update_user_status(&conn, id, status::APPROVED).unwrap();
        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.status, status::APPROVED);
        assert!(u.approved_at.is_some());
    }

    #[test]
    fn email_token_round_trip() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();

        insert_email_token(&conn, "tok123", uid, "verify").unwrap();

        // Wrong kind → None
        assert!(
            consume_email_token(&conn, "tok123", "approve")
                .unwrap()
                .is_none()
        );
        // Correct kind → Some
        assert_eq!(
            consume_email_token(&conn, "tok123", "verify").unwrap(),
            Some(uid)
        );
        // Already used → None
        assert!(
            consume_email_token(&conn, "tok123", "verify")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn update_password_changes_hash() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let id = insert_user(&conn, "a@b.com", "Alice", "Acme", "old_hash").unwrap();
        update_password(&conn, id, "new_hash").unwrap();
        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.password, "new_hash");
    }

    #[test]
    fn session_round_trip() {
        use crate::session;
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();

        let raw_token = "sess_abc";
        let token_hash = session::hash_token(raw_token);
        insert_session(&conn, &token_hash, uid, 168).unwrap();
        assert_eq!(validate_session(&conn, &token_hash).unwrap(), Some(uid));

        delete_session(&conn, &token_hash).unwrap();
        assert!(validate_session(&conn, &token_hash).unwrap().is_none());
    }

    #[test]
    fn tier_defaults_and_upgrades() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let id = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();

        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.tier, tier::SHADOW);

        update_user_tier(&conn, id, tier::INLINE_LICENSED).unwrap();
        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.tier, tier::INLINE_LICENSED);

        update_stripe_customer_id(&conn, id, "cus_test123").unwrap();
        let u = get_user_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(u.stripe_customer_id.as_deref(), Some("cus_test123"));
    }

    #[test]
    fn license_key_table_exists() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = 'license_keys'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn license_key_round_trip() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();
        update_user_status(&conn, uid, status::APPROVED).unwrap();

        let key_id = insert_license_key(&conn, uid, "veldra_test_key_001", "test label").unwrap();
        assert!(key_id > 0);

        let keys = get_license_keys_for_user(&conn, uid).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_value, "veldra_test_key_001");
        assert_eq!(keys[0].label, "test label");
        assert_eq!(keys[0].status, key_status::ACTIVE);

        // Validate returns user_id because user is approved.
        assert_eq!(
            validate_license_key(&conn, "veldra_test_key_001").unwrap(),
            Some(uid)
        );
    }

    #[test]
    fn license_key_validation_requires_approved_user() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();
        // User is still pending_verification.
        insert_license_key(&conn, uid, "veldra_test_key_002", "").unwrap();

        assert!(
            validate_license_key(&conn, "veldra_test_key_002")
                .unwrap()
                .is_none(),
            "key must not validate for non-approved user"
        );
    }

    #[test]
    fn license_key_revoke() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();
        update_user_status(&conn, uid, status::APPROVED).unwrap();

        let key_id = insert_license_key(&conn, uid, "veldra_test_key_003", "").unwrap();

        assert!(revoke_license_key(&conn, key_id, uid).unwrap());
        assert!(
            !revoke_license_key(&conn, key_id, uid).unwrap(),
            "double revoke returns false"
        );
        assert!(
            validate_license_key(&conn, "veldra_test_key_003")
                .unwrap()
                .is_none(),
            "revoked key must not validate"
        );
    }

    #[test]
    fn license_key_per_user_limit() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();

        for i in 0..5 {
            insert_license_key(&conn, uid, &format!("veldra_key_{i}"), "").unwrap();
        }

        let err = insert_license_key(&conn, uid, "veldra_key_overflow", "");
        assert!(err.is_err(), "6th key must be rejected");
    }

    #[test]
    fn license_key_revoked_does_not_count_toward_limit() {
        let pool = test_db();
        let conn = pool.lock().unwrap();
        let uid = insert_user(&conn, "a@b.com", "A", "O", "h").unwrap();

        for i in 0..5 {
            insert_license_key(&conn, uid, &format!("veldra_key_{i}"), "").unwrap();
        }

        // Revoke one key.
        revoke_license_key(&conn, 1, uid).unwrap();

        // Now inserting a 6th should succeed because one slot freed up.
        insert_license_key(&conn, uid, "veldra_key_replacement", "").unwrap();
    }

    // ── CL-21: License key serialization schema stability ──

    #[test]
    fn license_key_json_keys_stable() {
        // rg-feed-server and list_keys endpoint consumers rely on these fields.
        let key = LicenseKey {
            id: 1,
            user_id: 10,
            key_value: "veldra_test_abc".into(),
            label: "test".into(),
            status: key_status::ACTIVE.into(),
            created_at: "2026-03-10T00:00:00".into(),
            revoked_at: None,
        };
        let json = serde_json::to_value(&key).unwrap();
        let obj = json.as_object().unwrap();

        let expected_keys = [
            "id",
            "user_id",
            "key_value",
            "label",
            "status",
            "created_at",
            "revoked_at",
        ];
        assert_eq!(
            obj.len(),
            expected_keys.len(),
            "LicenseKey field count changed"
        );
        for k in &expected_keys {
            assert!(obj.contains_key(*k), "LicenseKey missing key '{k}'");
        }
    }
}

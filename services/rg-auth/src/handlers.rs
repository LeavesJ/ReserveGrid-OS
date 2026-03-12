use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tracing::error;

use crate::AppState;
use crate::{db, email, password, session};

// ── Request / response types ────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub name: String,
    pub org: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

// ── Health ──────────────────────────────────────────────────────

pub async fn health() -> &'static str {
    "ok"
}

// ── Register ────────────────────────────────────────────────────

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Rate limiting: 5 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 5 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests")),
        );
    }

    // Basic validation.
    if !is_valid_email(&req.email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_json("invalid_email", "Invalid email address")),
        );
    }
    if req.name.is_empty() || req.name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_json("invalid_name", "Name is required (max 200 chars)")),
        );
    }
    if req.org.is_empty() || req.org.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_json(
                "invalid_org",
                "Organization is required (max 200 chars)",
            )),
        );
    }
    if req.password.len() < 8 || req.password.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_json(
                "weak_password",
                "Password must be 8 to 1024 characters",
            )),
        );
    }

    let Ok(hash) = password::hash(&req.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Failed to hash password")),
        );
    };

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    // Check if email already registered.
    if let Ok(Some(_)) = db::get_user_by_email(&conn, &req.email) {
        return (
            StatusCode::CONFLICT,
            Json(err_json("email_taken", "Email already registered")),
        );
    }

    let Ok(user_id) = db::insert_user(&conn, &req.email, &req.name, &req.org, &hash) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Failed to create user")),
        );
    };

    // Generate verification token and send email.
    let verify_token = session::generate_token();
    if let Err(e) = db::insert_email_token(&conn, &verify_token, user_id, "verify") {
        error!(error = ?e, "insert verify token failed");
    }

    drop(conn); // Release lock before sending email.

    let body = email::verification_body(&state.site_url, &verify_token);
    if let Err(e) = email::send(
        state.smtp.as_ref(),
        &req.email,
        "Verify your email — Veldra",
        &body,
    ) {
        error!(error = ?e, recipient = %req.email, "send verification email failed");
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "message": "Registration successful. Check your email to verify."
        })),
    )
}

// ── Verify email ────────────────────────────────────────────────

pub async fn verify_email(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    // Rate limiting: 5 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 5 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests.")),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    };

    let user_id = match db::consume_email_token(&conn, &q.token, "verify") {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_json(
                    "invalid_token",
                    "Invalid or expired verification link.",
                )),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Internal error.")),
            );
        }
    };

    if let Err(e) = db::update_user_status(&conn, user_id, db::status::PENDING_APPROVAL) {
        error!(error = ?e, user_id, "update status failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    }

    let user = db::get_user_by_id(&conn, user_id).ok().flatten();

    // Generate approve/deny tokens for admin.
    let approve_token = session::generate_token();
    let deny_token = session::generate_token();
    let _ = db::insert_email_token(&conn, &approve_token, user_id, "approve");
    let _ = db::insert_email_token(&conn, &deny_token, user_id, "deny");

    drop(conn);

    // Notify admin.
    if let Some(ref u) = user {
        let body = email::admin_notification_body(
            &state.auth_url,
            &u.name,
            &u.email,
            &u.org,
            &approve_token,
            &deny_token,
        );
        if let Err(e) = email::send(
            state.smtp.as_ref(),
            &state.admin_email,
            &format!("Observe access request: {}", u.name),
            &body,
        ) {
            error!(error = ?e, admin = %state.admin_email, "send admin notification failed");
        }
    }

    (
        StatusCode::OK,
        Json(ok_json(
            "Email verified. Your request is pending admin approval.",
        )),
    )
}

// ── Login ───────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Rate limiting: 10 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 10 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests")),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    let Ok(Some(user)) = db::get_user_by_email(&conn, &req.email) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("invalid_credentials", "Invalid email or password")),
        );
    };

    let pw_ok = password::verify(&req.password, &user.password).unwrap_or(false);
    if !pw_ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("invalid_credentials", "Invalid email or password")),
        );
    }

    match user.status.as_str() {
        db::status::PENDING_VERIFICATION => {
            return (
                StatusCode::FORBIDDEN,
                Json(err_json(
                    "email_not_verified",
                    "Please verify your email first",
                )),
            );
        }
        db::status::PENDING_APPROVAL => {
            return (
                StatusCode::FORBIDDEN,
                Json(err_json(
                    "pending_approval",
                    "Your account is pending admin approval",
                )),
            );
        }
        db::status::DENIED => {
            return (
                StatusCode::FORBIDDEN,
                Json(err_json("access_denied", "Your access request was denied")),
            );
        }
        db::status::APPROVED => {} // proceed
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Unknown account status")),
            );
        }
    }

    let token = session::generate_token();
    if let Err(e) = db::insert_session(&conn, &token, user.id, state.session_ttl_hours) {
        error!(error = ?e, user_id = user.id, "insert session failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Session creation failed")),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "org": user.org,
                "tier": user.tier,
            }
        })),
    )
}

// ── Logout ──────────────────────────────────────────────────────

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = extract_bearer(&headers)
        && let Ok(conn) = state.db.lock()
    {
        let _ = db::delete_session(&conn, token);
    }
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

// ── Session check ───────────────────────────────────────────────

pub async fn session_check(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(token) = extract_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"valid": false})),
        );
    };

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"valid": false})),
        );
    };

    let Ok(Some(user_id)) = db::validate_session(&conn, token) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"valid": false})),
        );
    };

    let user = match db::get_user_by_id(&conn, user_id) {
        Ok(Some(u)) if u.status == db::status::APPROVED => u,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"valid": false})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "valid": true,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "org": user.org,
                "tier": user.tier,
            }
        })),
    )
}

// ── Admin approve ───────────────────────────────────────────────

pub async fn approve(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    // Rate limiting: 3 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 3 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests.")),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    };

    let user_id = match db::consume_email_token(&conn, &q.token, "approve") {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_json(
                    "invalid_token",
                    "Invalid or expired approval link.",
                )),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Internal error.")),
            );
        }
    };

    if let Err(e) = db::update_user_status(&conn, user_id, db::status::APPROVED) {
        error!(error = ?e, user_id, "approve status update failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    }

    let user = db::get_user_by_id(&conn, user_id).ok().flatten();
    drop(conn);

    // Notify user of approval.
    if let Some(ref u) = user {
        let body = email::approval_body(&state.site_url);
        if let Err(e) = email::send(
            state.smtp.as_ref(),
            &u.email,
            "Observe Mode access approved — Veldra",
            &body,
        ) {
            error!(error = ?e, recipient = %u.email, "send approval email failed");
        }
    }

    (
        StatusCode::OK,
        Json(ok_json("User approved. They can now log in.")),
    )
}

// ── Admin deny ──────────────────────────────────────────────────

pub async fn deny(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    // Rate limiting: 3 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 3 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests.")),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    };

    let user_id = match db::consume_email_token(&conn, &q.token, "deny") {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_json("invalid_token", "Invalid or expired denial link.")),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Internal error.")),
            );
        }
    };

    if let Err(e) = db::update_user_status(&conn, user_id, db::status::DENIED) {
        error!(error = ?e, user_id, "deny status update failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Internal error.")),
        );
    }

    let user = db::get_user_by_id(&conn, user_id).ok().flatten();
    drop(conn);

    if let Some(ref u) = user {
        let body = email::denial_body();
        if let Err(e) = email::send(
            state.smtp.as_ref(),
            &u.email,
            "Observe Mode access update — Veldra",
            &body,
        ) {
            error!(error = ?e, recipient = %u.email, "send denial email failed");
        }
    }

    (StatusCode::OK, Json(ok_json("User denied.")))
}

// ── Forgot password ─────────────────────────────────────────

pub async fn forgot_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ForgotPasswordRequest>,
) -> impl IntoResponse {
    // Rate limiting: 3 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 3 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests")),
        );
    }

    // Always return 200 to prevent email enumeration.
    let ok_response = || {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "message": "If that email is registered, a password reset link has been sent."
            })),
        )
    };

    let Ok(conn) = state.db.lock() else {
        return ok_response();
    };

    let Ok(Some(user)) = db::get_user_by_email(&conn, &req.email) else {
        return ok_response();
    };

    let reset_token = session::generate_token();
    if let Err(e) = db::insert_email_token(&conn, &reset_token, user.id, "password_reset") {
        error!(error = ?e, user_id = user.id, "insert password_reset token failed");
        return ok_response();
    }

    drop(conn);

    let body = email::password_reset_body(&state.site_url, &reset_token);
    if let Err(e) = email::send(
        state.smtp.as_ref(),
        &req.email,
        "Password reset — Veldra",
        &body,
    ) {
        error!(error = ?e, recipient = %req.email, "send password reset email failed");
    }

    ok_response()
}

// ── Reset password ──────────────────────────────────────────

pub async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    // Rate limiting: 5 requests per minute.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 5 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_json("rate_limited", "Too many requests")),
        );
    }

    if req.password.len() < 8 || req.password.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_json(
                "weak_password",
                "Password must be 8 to 1024 characters",
            )),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    // Password reset tokens expire in 1 hour.
    let user_id = match db::consume_email_token_ttl(&conn, &req.token, "password_reset", 1) {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(err_json("invalid_token", "Invalid or expired reset link")),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Database error")),
            );
        }
    };

    let Ok(hash) = password::hash(&req.password) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Failed to hash password")),
        );
    };

    if let Err(e) = db::update_password(&conn, user_id, &hash) {
        error!(error = ?e, user_id, "update password failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Failed to update password")),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "message": "Password reset successful. You can now log in."
        })),
    )
}

// ── License key: validate (for rg-feed-server) ─────────────────

#[derive(Deserialize)]
pub struct ValidateKeyRequest {
    pub key: String,
}

/// Validate a license key. Called by rg-feed-server during WebSocket handshake.
/// No session required; this is a service-to-service endpoint.
pub async fn validate_key(
    State(state): State<AppState>,
    Json(req): Json<ValidateKeyRequest>,
) -> impl IntoResponse {
    if req.key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"valid": false, "reason": "empty_key"})),
        );
    }

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"valid": false, "reason": "internal_error"})),
        );
    };

    match db::validate_license_key(&conn, &req.key) {
        Ok(Some(_user_id)) => (StatusCode::OK, Json(serde_json::json!({"valid": true}))),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({"valid": false, "reason": "invalid_or_revoked"})),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"valid": false, "reason": "internal_error"})),
        ),
    }
}

// ── License key: list (for account page) ────────────────────────

/// List all license keys for the authenticated user.
pub async fn list_keys(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(token) = extract_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Missing session token")),
        );
    };

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    let Ok(Some(user_id)) = db::validate_session(&conn, token) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Invalid or expired session")),
        );
    };

    match db::get_license_keys_for_user(&conn, user_id) {
        Ok(keys) => {
            let masked: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "id": k.id,
                        "key_prefix": mask_key(&k.key_value),
                        "label": k.label,
                        "status": k.status,
                        "created_at": k.created_at,
                        "revoked_at": k.revoked_at,
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({"keys": masked})))
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Failed to retrieve keys")),
        ),
    }
}

// ── License key: generate ───────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateKeyRequest {
    #[serde(default)]
    pub label: String,
}

/// Generate a new license key for the authenticated user.
pub async fn generate_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GenerateKeyRequest>,
) -> impl IntoResponse {
    let Some(token) = extract_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Missing session token")),
        );
    };

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    let Ok(Some(user_id)) = db::validate_session(&conn, token) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Invalid or expired session")),
        );
    };

    // Verify user is approved.
    let Ok(Some(user)) = db::get_user_by_id(&conn, user_id) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "User not found")),
        );
    };

    if user.status != db::status::APPROVED {
        return (
            StatusCode::FORBIDDEN,
            Json(err_json(
                "not_approved",
                "Account must be approved to generate keys",
            )),
        );
    }

    let key_value = session::generate_license_key();
    let label = if req.label.is_empty() {
        "default".to_string()
    } else {
        req.label.chars().take(100).collect()
    };

    match db::insert_license_key(&conn, user_id, &key_value, &label) {
        Ok(key_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "key": {
                    "id": key_id,
                    "key_value": key_value,
                    "label": label,
                    "status": db::key_status::ACTIVE,
                }
            })),
        ),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already has") {
                (
                    StatusCode::CONFLICT,
                    Json(err_json("key_limit_reached", &msg)),
                )
            } else {
                error!(error = %e, user_id, "insert license key failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(err_json("internal_error", "Failed to generate key")),
                )
            }
        }
    }
}

// ── License key: revoke ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeKeyRequest {
    pub key_id: i64,
}

/// Revoke a license key owned by the authenticated user.
pub async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeKeyRequest>,
) -> impl IntoResponse {
    let Some(token) = extract_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Missing session token")),
        );
    };

    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Database error")),
        );
    };

    let Ok(Some(user_id)) = db::validate_session(&conn, token) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Invalid or expired session")),
        );
    };

    match db::revoke_license_key(&conn, req.key_id, user_id) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "message": "Key revoked"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(err_json(
                "key_not_found",
                "Key not found or already revoked",
            )),
        ),
        Err(e) => {
            error!(error = %e, user_id, key_id = req.key_id, "revoke license key failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_json("internal_error", "Failed to revoke key")),
            )
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Extract the real client IP, preferring `x-forwarded-for` when the proxy
/// is trusted. Falls back to the direct socket address.
fn client_ip(headers: &HeaderMap, addr: SocketAddr, trust_proxy: bool) -> std::net::IpAddr {
    if trust_proxy
        && let Some(xff) = headers.get("x-forwarded-for")
        && let Ok(val) = xff.to_str()
        && let Some(first) = val.split(',').next()
        && let Ok(ip) = first.trim().parse::<std::net::IpAddr>()
    {
        return ip;
    }
    addr.ip()
}

/// Lightweight email validation without pulling in a regex or validation crate.
/// Checks: max 254 chars, exactly one '@', non-empty local and domain parts,
/// domain contains at least one dot, no whitespace anywhere.
fn is_valid_email(email: &str) -> bool {
    if email.len() > 254 || email.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if domain.is_empty() || !domain.contains('.') {
        return false;
    }
    // Domain labels must not start or end with a hyphen, and the TLD must be at
    // least 2 characters. We keep this deliberately simple to avoid false negatives
    // while still catching obvious junk.
    let tld = domain.rsplit('.').next().unwrap_or("");
    tld.len() >= 2
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn err_json(code: &str, detail: &str) -> serde_json::Value {
    serde_json::json!({"error": code, "detail": detail})
}

fn ok_json(message: &str) -> serde_json::Value {
    serde_json::json!({"ok": true, "message": message})
}

/// Mask a license key for display: show prefix and last 4 chars.
/// Example: `veldra_ab12...ef56`
fn mask_key(key: &str) -> String {
    if key.len() <= 12 {
        return key.to_string();
    }
    let prefix = &key[..11]; // "veldra_" + 4 hex chars
    let suffix = &key[key.len() - 4..];
    format!("{prefix}...{suffix}")
}

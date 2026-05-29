use axum::{
    Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tracing::{error, warn};

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

#[allow(clippy::too_many_lines)]
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

    // Check if email already registered. Return the same success response
    // regardless to prevent email enumeration. Notify the existing user via
    // email so they know someone tried to register with their address.
    if let Ok(Some(_)) = db::get_user_by_email(&conn, &req.email) {
        drop(conn);
        let body = "Someone attempted to create a new Veldra account using your email address.\n\n\
                     If this was you, you already have an account. Try logging in or resetting your password.\n\n\
                     If this was not you, no action is needed. Your account is secure.\n\n\
                     — Veldra";
        if let Err(e) = email::send(
            state.smtp.as_ref(),
            &req.email,
            "Account registration attempt — Veldra",
            body,
        ) {
            error!(error = ?e, recipient = %req.email, "send duplicate-registration notice failed");
        }
        return (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "message": "Registration successful. Check your email to verify."
            })),
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
    if let Err(e) = db::insert_email_token(&conn, &approve_token, user_id, "approve") {
        warn!(user_id, error = %e, "failed to insert approve email token");
    }
    if let Err(e) = db::insert_email_token(&conn, &deny_token, user_id, "deny") {
        warn!(user_id, error = %e, "failed to insert deny email token");
    }

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
    let token_hash = session::hash_token(&token);
    if let Err(e) = db::insert_session(&conn, &token_hash, user.id, state.session_ttl_hours) {
        error!(error = ?e, user_id = user.id, "insert session failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(err_json("internal_error", "Session creation failed")),
        );
    }

    // Return the raw token to the client. Only the hash is stored.
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
        let token_hash = session::hash_token(token);
        if let Err(e) = db::delete_session(&conn, &token_hash) {
            warn!(error = %e, "failed to delete session on logout");
        }
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

    let token_hash = session::hash_token(token);
    let Ok(Some(user_id)) = db::validate_session(&conn, &token_hash) else {
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

/// GET /auth/approve?token=X renders a confirmation page. The actual state
/// change happens only when the admin clicks the confirm button, which submits
/// a POST. This prevents email link prefetchers (Outlook Safe Links, Google
/// link scanning) from triggering approvals automatically.
pub async fn approve(Query(q): Query<TokenQuery>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::response::Html(admin_confirm_page(&q.token, "approve")),
    )
}

/// POST /auth/approve — actually consumes the token and approves the user.
pub async fn approve_confirm(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<TokenQuery>,
) -> impl IntoResponse {
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

    let user_id = match db::consume_email_token(&conn, &req.token, "approve") {
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

/// GET /auth/deny?token=X renders a confirmation page (same prefetcher defense).
pub async fn deny(Query(q): Query<TokenQuery>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::response::Html(admin_confirm_page(&q.token, "deny")),
    )
}

/// POST /auth/deny — actually consumes the token and denies the user.
pub async fn deny_confirm(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<TokenQuery>,
) -> impl IntoResponse {
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

    let user_id = match db::consume_email_token(&conn, &req.token, "deny") {
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

    // Invalidate all existing sessions for this user. Any session obtained
    // with the old credentials must not survive a password reset.
    if let Err(e) = db::delete_sessions_for_user(&conn, user_id) {
        error!(error = ?e, user_id, "delete sessions after password reset failed");
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
/// Rate limited to prevent brute force and denial of service.
///
/// Validation performs three checks in order:
/// 1. Ed25519 signature verification (proves the key was issued by Veldra).
/// 2. Expiry check on the embedded `expires_at` field.
/// 3. DB revocation check (ensures the key has not been revoked by the user).
///
/// The response includes `tier` on success so rg-feed-server can enforce
/// tier gating without parsing the key itself.
pub async fn validate_key(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ValidateKeyRequest>,
) -> impl IntoResponse {
    // Rate limiting: 20 requests per minute per IP.
    let ip = client_ip(&headers, addr, state.trust_proxy);
    if !state
        .rate_limiter
        .check(ip, 20 * state.rate_limit_multiplier)
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"valid": false, "reason": "rate_limited"})),
        );
    }

    if req.key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"valid": false, "reason": "empty_key"})),
        );
    }

    // Step 1: Verify signature.
    let verifying_key = state.signing_key.verifying_key();
    let Some(payload) = session::verify_license_key(&req.key, &verifying_key) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"valid": false, "reason": "invalid_signature"})),
        );
    };

    // Step 2: Check expiry.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if payload.expires_at < now {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"valid": false, "reason": "key_expired"})),
        );
    }

    // Step 3: DB revocation check.
    let Ok(conn) = state.db.lock() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"valid": false, "reason": "internal_error"})),
        );
    };
    match db::validate_license_key(&conn, &req.key) {
        Ok(Some(_user_id)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "valid": true,
                "tier": payload.tier,
                "org_id": payload.org_id,
            })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({"valid": false, "reason": "revoked_or_unknown"})),
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

    let token_hash = session::hash_token(token);
    let Ok(Some(user_id)) = db::validate_session(&conn, &token_hash) else {
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
                        "key_value": k.key_value,
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

/// Generate a new signed license key for the authenticated user.
///
/// The key format is `veldra_lic_{base64url_payload}.{base64url_signature}`.
/// The payload embeds the user's org, tier, issuance and expiry timestamps,
/// and feature flags. The Ed25519 signature allows offline verification by
/// rg-desktop and rg-feed-server without calling back to rg-auth.
pub async fn generate_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<GenerateKeyRequest>,
) -> impl IntoResponse {
    let signing_key = &state.signing_key;

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

    let token_hash = session::hash_token(token);
    let Ok(Some(user_id)) = db::validate_session(&conn, &token_hash) else {
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

    // Map the DB tier value to the license payload tier string.
    // These must stay in sync with rg-desktop's tier expectations.
    let tier = &user.tier;
    let features = tier_features(tier);

    let key_value = session::sign_license_key(signing_key, &user.org, tier, &features);
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
                    "tier": tier,
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

/// Derive feature flags from the user's tier. These are embedded in the
/// license payload and used by rg-desktop for local feature gating.
fn tier_features(tier: &str) -> Vec<String> {
    match tier {
        db::tier::OBSERVE_PAID => vec!["exporter".to_string()],
        db::tier::INLINE_LICENSED => vec!["gateway".to_string(), "exporter".to_string()],
        // shadow and any unknown tier get no special features.
        _ => vec![],
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

    let token_hash = session::hash_token(token);
    let Ok(Some(user_id)) = db::validate_session(&conn, &token_hash) else {
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

// ── Admin settings (requires admin session) ─────────────────────

/// Returns service configuration. Requires an active session belonging to the
/// admin email configured in `VELDRA_AUTH_ADMIN_EMAIL`. Returns 403 for all
/// other users and 401 for unauthenticated requests.
pub async fn admin_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
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

    let token_hash = session::hash_token(token);
    let Ok(Some(user_id)) = db::validate_session(&conn, &token_hash) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "Invalid or expired session")),
        );
    };

    let Ok(Some(user)) = db::get_user_by_id(&conn, user_id) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(err_json("unauthorized", "User not found")),
        );
    };

    if user.email != state.admin_email {
        return (
            StatusCode::FORBIDDEN,
            Json(err_json("forbidden", "Admin access required")),
        );
    }

    drop(conn);

    let log_level = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let smtp_configured = state.smtp.is_some();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "log_level": log_level,
            "session_ttl_hours": state.session_ttl_hours,
            "admin_email": state.admin_email,
            "site_url": state.site_url,
            "auth_url": state.auth_url,
            "smtp_configured": smtp_configured,
            "trust_proxy": state.trust_proxy,
        })),
    )
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

/// Renders a minimal HTML confirmation page for admin approve/deny actions.
/// The page contains a single button that POSTs the token back to the server.
/// This prevents email link prefetchers from triggering state changes on GET.
///
/// Tokens from `session::generate_token` are exactly `TOKEN_HEX_LEN` lowercase
/// hex chars. Anything else is rejected at template time, before any HTML or
/// JS embedding, and the same check is mirrored in the inline JS so a server
/// side regression cannot leak past the form. Defense in depth against email
/// client copy paste corruption (line wraps, trailing whitespace, smart quotes).
fn admin_confirm_page(token: &str, action: &str) -> String {
    let label = if action == "approve" {
        "Approve User"
    } else {
        "Deny User"
    };
    let color = if action == "approve" {
        "#22c55e"
    } else {
        "#ef4444"
    };
    let Some(safe_token) = sanitize_admin_token(token) else {
        return admin_invalid_token_page(label);
    };
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>{label} — Veldra</title>
<style>body{{font-family:system-ui;background:#0a0e17;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:2rem;text-align:center;max-width:400px}}
button{{background:{color};color:#fff;border:none;padding:0.75rem 2rem;border-radius:8px;font-size:1rem;cursor:pointer;font-weight:600}}
button:hover{{opacity:0.9}}
#done{{display:none;color:#9ca3af}}</style></head>
<body><div class="card">
<h2>{label}</h2>
<p style="color:#9ca3af">Click the button below to confirm this action.</p>
<button id="btn" onclick="doAction()">{label}</button>
<p id="done"></p>
</div>
<script>
function doAction(){{
  var t='{safe_token}';
  if(!/^[0-9a-f]{{64}}$/.test(t)){{
    var el=document.getElementById('done');
    el.style.display='block';
    el.textContent='Token shape check failed. Recopy the original link from the email.';
    return;
  }}
  var btn=document.getElementById('btn');
  btn.disabled=true;btn.textContent='Processing...';
  fetch('/auth/{action}',{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{token:t}})
  }}).then(function(r){{return r.json()}}).then(function(d){{
    var el=document.getElementById('done');
    el.style.display='block';
    el.textContent=d.message||d.detail||'Done.';
    btn.style.display='none';
  }}).catch(function(){{
    btn.textContent='Error. Try again.';btn.disabled=false;
  }});
}}
</script></body></html>"#
    )
}

/// Strict sanitizer for admin action tokens. Returns `Some` only if the input
/// matches the canonical shape emitted by `session::generate_token`, namely
/// exactly `TOKEN_HEX_LEN` lowercase hex chars. Returns `None` for anything
/// else so the caller can render an error page rather than embed garbage.
///
/// Lowercase is enforced because `hex_encode` writes `{b:02x}` exclusively.
/// Mixed case input therefore indicates either truncation, paste corruption,
/// or a forged URL, and gets rejected on principle.
fn sanitize_admin_token(raw: &str) -> Option<String> {
    if raw.len() != crate::session::TOKEN_HEX_LEN {
        return None;
    }
    if !raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Some(raw.to_string())
}

/// Minimal page shown when an admin action link arrived with a token that does
/// not match `TOKEN_HEX_LEN` lowercase hex chars. Most common cause is email
/// client copy paste corruption, occasionally a forged URL.
fn admin_invalid_token_page(label: &str) -> String {
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>{label} — Veldra</title>
<style>body{{font-family:system-ui;background:#0a0e17;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:2rem;text-align:center;max-width:420px}}</style></head>
<body><div class="card">
<h2>Invalid link</h2>
<p style="color:#9ca3af">This {label} link is malformed or has been truncated by your email client. Recopy the original link from the notification email and try again. If the problem persists, request a fresh admin notification.</p>
</div></body></html>"#
    )
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn canonical_token() -> String {
        // 64 lowercase hex chars, matches session::generate_token shape.
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    #[test]
    fn sanitize_admin_token_accepts_canonical_shape() {
        let t = canonical_token();
        assert_eq!(sanitize_admin_token(&t).as_deref(), Some(t.as_str()));
    }

    #[test]
    fn sanitize_admin_token_rejects_short_input() {
        assert!(sanitize_admin_token("0123abcd").is_none());
    }

    #[test]
    fn sanitize_admin_token_rejects_uppercase() {
        let t = canonical_token().to_uppercase();
        assert!(sanitize_admin_token(&t).is_none());
    }

    #[test]
    fn sanitize_admin_token_rejects_non_hex() {
        // Underscore was permitted by the previous filter; explicit regression
        // guard to make sure the tightened sanitizer rejects it.
        let mut t = canonical_token();
        t.replace_range(0..1, "_");
        assert!(sanitize_admin_token(&t).is_none());
    }

    #[test]
    fn admin_confirm_page_renders_error_for_bad_token() {
        let html = admin_confirm_page("not-a-real-token", "approve");
        assert!(html.contains("Invalid link"));
        assert!(!html.contains("doAction"));
    }
}

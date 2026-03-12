use anyhow::{Context, Result};
use tracing::info;

/// SMTP configuration parsed from environment variables.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub from_address: String,
}

impl SmtpConfig {
    /// Returns None if SMTP env vars are not set (email disabled).
    pub fn from_env() -> Option<Self> {
        let host = std::env::var("VELDRA_AUTH_SMTP_HOST").ok()?;
        let port = std::env::var("VELDRA_AUTH_SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(587);
        let user = std::env::var("VELDRA_AUTH_SMTP_USER").ok()?;
        let pass = std::env::var("VELDRA_AUTH_SMTP_PASS").ok()?;
        let from_address = std::env::var("VELDRA_AUTH_SMTP_FROM").unwrap_or_else(|_| user.clone());

        Some(Self {
            host,
            port,
            user,
            pass,
            from_address,
        })
    }
}

/// Send an email via SMTP. Returns Ok(()) or error.
///
/// Always logs the email body via tracing so that integration tests can extract
/// tokens from `docker logs` regardless of whether SMTP is configured.
/// If `smtp` is None, the tracing log IS the delivery (dev mode).
/// If `smtp` is Some, the log fires first, then real SMTP delivery is attempted.
pub fn send(smtp: Option<&SmtpConfig>, to: &str, subject: &str, body: &str) -> Result<()> {
    info!(to = to, subject = subject, body = body, "email_send");
    if let Some(cfg) = smtp {
        send_smtp(cfg, to, subject, body)
    } else {
        Ok(())
    }
}

fn send_smtp(cfg: &SmtpConfig, to: &str, subject: &str, body: &str) -> Result<()> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let email = Message::builder()
        .from(cfg.from_address.parse().context("parse from address")?)
        .to(to.parse().context("parse to address")?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .context("build email message")?;

    let creds = Credentials::new(cfg.user.clone(), cfg.pass.clone());

    let mailer = SmtpTransport::starttls_relay(&cfg.host)
        .context("smtp relay")?
        .port(cfg.port)
        .credentials(creds)
        .build();

    mailer.send(&email).context("send email")?;
    Ok(())
}

// ── Email templates ─────────────────────────────────────────────

pub fn verification_body(site_url: &str, token: &str) -> String {
    format!(
        "Welcome to ReserveGrid OS Observe Mode.\n\n\
         Click the link below to verify your email address:\n\n\
         {site_url}/verify/?token={token}\n\n\
         This link expires in 7 days.\n\n\
         — Veldra"
    )
}

pub fn admin_notification_body(
    base_url: &str,
    user_name: &str,
    user_email: &str,
    user_org: &str,
    approve_token: &str,
    deny_token: &str,
) -> String {
    format!(
        "New Observe Mode access request:\n\n\
         Name:  {user_name}\n\
         Email: {user_email}\n\
         Org:   {user_org}\n\n\
         Approve: {base_url}/auth/approve?token={approve_token}\n\
         Deny:    {base_url}/auth/deny?token={deny_token}\n\n\
         — rg-auth"
    )
}

pub fn approval_body(base_url: &str) -> String {
    format!(
        "Your request for ReserveGrid OS Observe Mode access has been approved.\n\n\
         You can now log in at:\n\
         {base_url}/login/\n\n\
         — Veldra"
    )
}

pub fn password_reset_body(site_url: &str, token: &str) -> String {
    format!(
        "You requested a password reset for your ReserveGrid OS account.\n\n\
         Click the link below to set a new password:\n\n\
         {site_url}/reset-password/?token={token}\n\n\
         This link expires in 1 hour. If you did not request this, ignore this email.\n\n\
         — Veldra"
    )
}

pub fn denial_body() -> String {
    "Your request for ReserveGrid OS Observe Mode access has been denied.\n\n\
     If you believe this is an error, please contact us.\n\n\
     — Veldra"
        .to_string()
}

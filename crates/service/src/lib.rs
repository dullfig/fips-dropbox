//! # service — business logic
//!
//! The operations the HTTP layer and the sender-agent call. This is where
//! audit events get emitted, notifications get sent, and policy gets applied.
//!
//! All database work runs inside `tokio::task::spawn_blocking` so blocking
//! SQLite calls do not stall the async runtime. The single `std::sync::Mutex`
//! around the Store is fine for a one-shop deployment; if we ever need more
//! concurrency we can switch to a connection pool.

use std::sync::Arc;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub use storage::{IssuedSession, Session, Share, User, UserRole, Vendor};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("storage: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("audit: {0}")]
    Audit(#[from] audit::AuditError),
    #[error("notifier: {0}")]
    Notifier(#[from] notifier::NotifyError),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("not found")]
    NotFound,
    #[error("share unavailable (expired, revoked, or exhausted)")]
    ShareUnavailable,
    #[error("internal: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

pub struct App {
    pub store: Arc<std::sync::Mutex<storage::Store>>,
    pub kek: Arc<crypto::KekManager>,
    pub audit: Arc<std::sync::Mutex<audit::Log>>,
    pub email: Arc<dyn notifier::EmailSender>,
    pub sms: Arc<dyn notifier::SmsSender>,
    pub public_base_url: String,
    /// FIPS mode status captured at startup (from BCryptGetFipsAlgorithmMode).
    /// Static after boot; services restart to re-check.
    pub fips_mode_enabled: bool,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub ip: String,
    pub user_agent: String,
}

pub struct NewShareRequest {
    pub print_filename: String,
    pub print_bytes: Vec<u8>,
    pub vendor_email: String,
    pub vendor_phone: Option<String>,
    pub vendor_display_name: String,
    pub expires_in_hours: u32,
    pub max_downloads: u32,
    pub note: Option<String>,
    pub cui_attested: bool,
    pub created_by: Uuid,
    pub ip: String,
    pub user_agent: String,
}

pub struct ShareCreated {
    pub share_id: Uuid,
    pub share_url: String,
    pub access_code: String,
    pub vendor_email: String,
    pub vendor_phone: Option<String>,
}

pub struct RedeemRequest {
    pub token: String,
    pub access_code: String,
    pub ip: String,
    pub user_agent: String,
}

pub struct RedeemResponse {
    pub filename: String,
    pub content: Vec<u8>,
    pub sha256: [u8; 32],
}

// ---------------------------------------------------------------------------
// App methods
// ---------------------------------------------------------------------------

impl App {
    // ----- auth ------------------------------------------------------------

    pub async fn login(&self, req: LoginRequest) -> Result<IssuedSession> {
        let store = self.store.clone();
        let audit = self.audit.clone();

        tokio::task::spawn_blocking(move || -> Result<IssuedSession> {
            let s = store.lock().map_err(poisoned)?;
            let user = storage::users::verify_password(&s.conn, &req.email, &req.password)?
                .ok_or(ServiceError::InvalidCredentials)?;
            let issued = storage::sessions::create(
                &s.conn,
                &user.id,
                &req.ip,
                &req.user_agent,
                storage::sessions::DEFAULT_TTL_HOURS,
            )?;
            let mut a = audit.lock().map_err(poisoned)?;
            write_event(
                &mut a,
                "auth.login",
                audit::Outcome::Success,
                Some(user.id),
                &req.ip,
                &req.user_agent,
                serde_json::json!({ "user_id": user.id.to_string() }),
                serde_json::json!({}),
            )?;
            Ok(issued)
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    }

    pub async fn logout(&self, raw_token: String, ip: String, ua: String) -> Result<()> {
        let store = self.store.clone();
        let audit = self.audit.clone();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let s = store.lock().map_err(poisoned)?;
            let sess = storage::sessions::find_valid(&s.conn, &raw_token)?;
            storage::sessions::revoke(&s.conn, &raw_token)?;
            let user_id = sess.map(|s| s.user_id);
            let mut a = audit.lock().map_err(poisoned)?;
            write_event(
                &mut a,
                "auth.logout",
                audit::Outcome::Success,
                user_id,
                &ip,
                &ua,
                serde_json::json!({}),
                serde_json::json!({}),
            )?;
            Ok(())
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    }

    pub async fn find_authenticated(
        &self,
        raw_token: String,
    ) -> Result<Option<(Session, User)>> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<(Session, User)>> {
            let s = store.lock().map_err(poisoned)?;
            let sess = match storage::sessions::find_valid(&s.conn, &raw_token)? {
                Some(s) => s,
                None => return Ok(None),
            };
            let user = match storage::users::find_by_id(&s.conn, &sess.user_id)? {
                Some(u) => u,
                None => return Ok(None),
            };
            if user.disabled_at.is_some() {
                return Ok(None);
            }
            Ok(Some((sess, user)))
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    }

    // ----- shares ----------------------------------------------------------

    pub async fn create_share(&self, req: NewShareRequest) -> Result<ShareCreated> {
        let store = self.store.clone();
        let kek = self.kek.clone();
        let audit = self.audit.clone();

        let created = tokio::task::spawn_blocking(
            move || -> Result<(Share, storage::ShareSecrets, Vendor, String, usize)> {
                let s = store.lock().map_err(poisoned)?;

                let vendor = match storage::vendors::find_by_email(&s.conn, &req.vendor_email)? {
                    Some(v) => v,
                    None => storage::vendors::create(
                        &s.conn,
                        &req.vendor_display_name,
                        &req.vendor_email,
                        req.vendor_phone.as_deref(),
                        &req.created_by,
                    )?,
                };

                let print_store = storage::PrintStore::new(&s.conn, &s.blobs_dir, &kek);
                let print = print_store.insert(
                    &req.print_filename,
                    &req.print_bytes,
                    req.created_by,
                    req.cui_attested,
                )?;

                let expires_at =
                    OffsetDateTime::now_utc() + Duration::hours(req.expires_in_hours as i64);
                let (share, secrets) = storage::shares::create(
                    &s.conn,
                    &print.id,
                    &vendor.id,
                    expires_at,
                    req.max_downloads,
                    req.note.as_deref(),
                    &req.created_by,
                )?;

                let mut a = audit.lock().map_err(poisoned)?;
                write_event(
                    &mut a,
                    "share.created",
                    audit::Outcome::Success,
                    Some(req.created_by),
                    &req.ip,
                    &req.user_agent,
                    serde_json::json!({
                        "share_id": share.id.to_string(),
                        "print_id": print.id.to_string(),
                        "vendor_id": vendor.id.to_string(),
                    }),
                    serde_json::json!({
                        "filename": req.print_filename,
                        "size_bytes": req.print_bytes.len(),
                        "max_downloads": req.max_downloads,
                        "expires_in_hours": req.expires_in_hours,
                        "note_present": req.note.is_some(),
                    }),
                )?;

                Ok((share, secrets, vendor, req.print_filename, req.print_bytes.len()))
            },
        )
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))??;

        let (share, secrets, vendor, _filename, _size) = created;
        let share_url = format!(
            "{}/r/{}",
            self.public_base_url.trim_end_matches('/'),
            secrets.url_token
        );

        // Fire notifications; log on failure but do not fail the share —
        // the admin can re-deliver the link and code from the dashboard.
        let email_subject = "A secure file has been shared with you";
        let email_body = format!(
            "Open: {}\n\nYour access code was sent to your phone separately.\n",
            share_url
        );
        if let Err(e) = self
            .email
            .send(&vendor.primary_email, email_subject, &email_body, &email_body)
            .await
        {
            tracing::warn!(?e, vendor = %vendor.primary_email, "share email failed");
        }
        if let Some(phone) = vendor.primary_phone.as_deref() {
            let sms = format!(
                "Secure share access code: {} (expires in {}h)",
                secrets.access_code, req.expires_in_hours
            );
            if let Err(e) = self.sms.send(phone, &sms).await {
                tracing::warn!(?e, "share SMS failed");
            }
        }

        Ok(ShareCreated {
            share_id: share.id,
            share_url,
            access_code: secrets.access_code,
            vendor_email: vendor.primary_email,
            vendor_phone: vendor.primary_phone,
        })
    }

    pub async fn redeem_share(&self, req: RedeemRequest) -> Result<RedeemResponse> {
        let store = self.store.clone();
        let kek = self.kek.clone();
        let audit = self.audit.clone();

        tokio::task::spawn_blocking(move || -> Result<RedeemResponse> {
            let s = store.lock().map_err(poisoned)?;

            let token_hash = crypto::hash::sha256(req.token.as_bytes())?;
            let share = storage::shares::find_by_token_hash(&s.conn, &token_hash)?
                .ok_or(ServiceError::NotFound)?;

            if !storage::shares::verify_access_code(&share, &req.access_code)? {
                let mut a = audit.lock().map_err(poisoned)?;
                write_event(
                    &mut a,
                    "share.redeem",
                    audit::Outcome::Denied,
                    None,
                    &req.ip,
                    &req.user_agent,
                    serde_json::json!({ "share_id": share.id.to_string() }),
                    serde_json::json!({ "reason": "bad_access_code" }),
                )?;
                return Err(ServiceError::InvalidCredentials);
            }

            if !storage::shares::try_consume_download(&s.conn, &share.id)? {
                let mut a = audit.lock().map_err(poisoned)?;
                write_event(
                    &mut a,
                    "share.redeem",
                    audit::Outcome::Denied,
                    None,
                    &req.ip,
                    &req.user_agent,
                    serde_json::json!({ "share_id": share.id.to_string() }),
                    serde_json::json!({ "reason": "unavailable" }),
                )?;
                return Err(ServiceError::ShareUnavailable);
            }

            let print_store = storage::PrintStore::new(&s.conn, &s.blobs_dir, &kek);
            let print = print_store
                .find(&share.print_id)?
                .ok_or(ServiceError::NotFound)?;
            let content = print_store.read_blob(&share.print_id)?;

            let mut a = audit.lock().map_err(poisoned)?;
            write_event(
                &mut a,
                "share.redeem",
                audit::Outcome::Success,
                None,
                &req.ip,
                &req.user_agent,
                serde_json::json!({
                    "share_id": share.id.to_string(),
                    "print_id": print.id.to_string(),
                    "vendor_id": share.vendor_id.to_string(),
                }),
                serde_json::json!({
                    "filename": print.filename,
                    "size_bytes": print.size_bytes,
                }),
            )?;

            Ok(RedeemResponse {
                filename: print.filename,
                content,
                sha256: print.sha256_plaintext,
            })
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    }

    pub async fn revoke_share(
        &self,
        share_id: Uuid,
        by: Uuid,
        ip: String,
        ua: String,
    ) -> Result<()> {
        let store = self.store.clone();
        let audit = self.audit.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let s = store.lock().map_err(poisoned)?;
            storage::shares::revoke(&s.conn, &share_id)?;
            let mut a = audit.lock().map_err(poisoned)?;
            write_event(
                &mut a,
                "share.revoked",
                audit::Outcome::Success,
                Some(by),
                &ip,
                &ua,
                serde_json::json!({ "share_id": share_id.to_string() }),
                serde_json::json!({}),
            )?;
            Ok(())
        })
        .await
        .map_err(|e| ServiceError::Internal(e.to_string()))?
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn poisoned<T>(_: std::sync::PoisonError<T>) -> ServiceError {
    ServiceError::Internal("mutex poisoned".into())
}

fn write_event(
    log: &mut audit::Log,
    name: &str,
    outcome: audit::Outcome,
    user_id: Option<Uuid>,
    ip: &str,
    ua: &str,
    target: serde_json::Value,
    meta: serde_json::Value,
) -> Result<()> {
    log.write(audit::Event {
        ts: OffsetDateTime::now_utc(),
        event: name.to_string(),
        actor: audit::Actor {
            user_id: user_id.map(|u| u.to_string()),
            ip: ip.to_string(),
            ua: ua.to_string(),
        },
        target,
        outcome,
        meta,
        prev_hash: String::new(),
        hash: String::new(),
    })?;
    Ok(())
}

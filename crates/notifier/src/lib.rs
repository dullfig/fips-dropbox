//! # notifier — pluggable email + SMS
//!
//! Email goes out via SMTP (the shop's O365 tenant or an SES-like relay).
//! SMS goes out via Twilio for MVP; the trait lets us swap to Bandwidth,
//! AWS SNS, or Twilio-Gov (FedRAMP Moderate) later.

use async_trait::async_trait;
use thiserror::Error;

pub mod smtp;
pub mod twilio;

pub use smtp::{SmtpConfig, SmtpSender, TlsMode};

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("provider config invalid: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, NotifyError>;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(
        &self,
        to: &str,
        subject: &str,
        body_text: &str,
        body_html: &str,
    ) -> Result<()>;
}

#[async_trait]
pub trait SmsSender: Send + Sync {
    async fn send(&self, to_e164: &str, body: &str) -> Result<()>;
}

/// Null sender useful for dev and unit tests. Logs and returns Ok.
pub struct Null;

#[async_trait]
impl EmailSender for Null {
    async fn send(&self, to: &str, subject: &str, _text: &str, _html: &str) -> Result<()> {
        tracing::info!(%to, %subject, "notifier::Null email");
        Ok(())
    }
}

#[async_trait]
impl SmsSender for Null {
    async fn send(&self, to: &str, body: &str) -> Result<()> {
        tracing::info!(%to, %body, "notifier::Null sms");
        Ok(())
    }
}

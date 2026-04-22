//! SMTP sender using `lettre` with native-tls (Schannel on Windows).
//!
//! Two TLS modes supported:
//!   * StartTls — connect in clear text on port 587, upgrade via STARTTLS.
//!                This is what Office 365, Gmail, and most corporate relays use.
//!   * ImplicitTls — connect with TLS from the start on port 465. Older.
//!
//! We do NOT support plaintext SMTP. If a shop's relay can't do either TLS
//! mode, they shouldn't be relaying notifications about CUI through it.

use async_trait::async_trait;
use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Deserialize;

use crate::{EmailSender, NotifyError, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    #[serde(default)]
    pub from_display_name: Option<String>,
    #[serde(default)]
    pub tls: TlsMode,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Starttls,
    #[serde(alias = "implicit", alias = "implicit_tls", alias = "implicittls")]
    ImplicitTls,
}

pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    host: String,
    port: u16,
}

impl SmtpSender {
    pub fn new(cfg: SmtpConfig) -> Result<Self> {
        let from_addr: Address = cfg.from_address.parse().map_err(|e| {
            NotifyError::Config(format!("bad from_address '{}': {}", cfg.from_address, e))
        })?;
        let from = Mailbox::new(cfg.from_display_name.clone(), from_addr);

        let creds = Credentials::new(cfg.username, cfg.password);
        let builder = match cfg.tls {
            TlsMode::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                .map_err(|e| NotifyError::Config(format!("starttls_relay: {}", e)))?,
            TlsMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                .map_err(|e| NotifyError::Config(format!("relay: {}", e)))?,
        };
        let transport = builder.port(cfg.port).credentials(creds).build();

        Ok(Self {
            transport,
            from,
            host: cfg.host,
            port: cfg.port,
        })
    }

    /// Short human-readable summary for logs and dashboard status.
    pub fn summary(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[async_trait]
impl EmailSender for SmtpSender {
    async fn send(
        &self,
        to: &str,
        subject: &str,
        body_text: &str,
        body_html: &str,
    ) -> Result<()> {
        let to_addr: Address = to
            .parse()
            .map_err(|e| NotifyError::Transport(format!("bad to '{}': {}", to, e)))?;
        let to_mb = Mailbox::new(None, to_addr);

        let email = Message::builder()
            .from(self.from.clone())
            .to(to_mb)
            .subject(subject)
            .multipart(MultiPart::alternative_plain_html(
                body_text.to_string(),
                body_html.to_string(),
            ))
            .map_err(|e| NotifyError::Transport(format!("build message: {}", e)))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| NotifyError::Transport(format!("send: {}", e)))?;
        tracing::info!(%to, host = %self.host, "smtp sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_cfg() -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.invalid".into(),
            port: 587,
            username: "user".into(),
            password: "pass".into(),
            from_address: "share@example.com".into(),
            from_display_name: Some("GRM Share".into()),
            tls: TlsMode::Starttls,
        }
    }

    #[test]
    fn construct_succeeds_with_valid_config() {
        let s = SmtpSender::new(valid_cfg()).unwrap();
        assert_eq!(s.summary(), "smtp.example.invalid:587");
    }

    #[test]
    fn rejects_bad_from_address() {
        let mut cfg = valid_cfg();
        cfg.from_address = "not an email".into();
        let r = SmtpSender::new(cfg);
        assert!(matches!(r, Err(NotifyError::Config(_))));
    }

    #[test]
    fn tls_mode_parses_both_spellings() {
        let toml_impl = r#"
            host = "h"
            port = 465
            username = "u"
            password = "p"
            from_address = "a@b.c"
            tls = "implicit_tls"
        "#;
        let cfg: SmtpConfig = toml::from_str(toml_impl).unwrap();
        assert!(matches!(cfg.tls, TlsMode::ImplicitTls));

        let toml_start = r#"
            host = "h"
            port = 587
            username = "u"
            password = "p"
            from_address = "a@b.c"
        "#;
        let cfg: SmtpConfig = toml::from_str(toml_start).unwrap();
        assert!(matches!(cfg.tls, TlsMode::Starttls));
    }
}

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub bind_address: String,
    pub public_base_url: String,
    pub db_path: PathBuf,
    pub blobs_dir: PathBuf,
    pub audit_log_path: PathBuf,
    pub kek_path: PathBuf,
    /// Optional SMTP relay. When absent, email delivery falls back to the
    /// Null sender (access codes must be delivered manually).
    #[serde(default)]
    pub smtp: Option<notifier::SmtpConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8080".into(),
            public_base_url: "http://localhost:8080".into(),
            db_path: PathBuf::from(r"C:\ProgramData\FipsDropbox\app.db"),
            blobs_dir: PathBuf::from(r"C:\ProgramData\FipsDropbox\blobs"),
            audit_log_path: PathBuf::from(r"C:\ProgramData\FipsDropbox\logs\audit.jsonl"),
            kek_path: PathBuf::from(r"C:\ProgramData\FipsDropbox\kek.bin"),
            smtp: None,
        }
    }
}

pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Config> {
    let path = path.as_ref();
    if !path.exists() {
        tracing::warn!(?path, "config file missing; using defaults");
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&text)?)
}

pub fn config_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CUISHARE_CONFIG")
            .unwrap_or_else(|_| r"C:\ProgramData\FipsDropbox\config.toml".to_string()),
    )
}

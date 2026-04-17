//! # audit — hash-chained append-only log
//!
//! Every event is one JSON object on its own line. Each event carries a
//! `prev_hash` pointing at the SHA-256 of the previous line (minus its own
//! hash field), plus its own `hash`. Tampering is detectable: recompute any
//! line's hash and compare to the next line's `prev_hash`.
//!
//! The file is the canonical record; database mirrors (if any) are for
//! convenience only. An assessor wants the raw JSONL.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;

pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub user_id: Option<String>,
    pub ip: String,
    pub ua: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub event: String,
    pub actor: Actor,
    pub target: serde_json::Value,
    pub outcome: Outcome,
    pub meta: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

pub struct Log {
    path: PathBuf,
    prev_hash: String,
}

impl Log {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let prev_hash = load_last_hash(&path)?;
        Ok(Self { path, prev_hash })
    }

    pub fn write(&mut self, mut ev: Event) -> Result<()> {
        ev.prev_hash = self.prev_hash.clone();
        ev.hash = String::new();

        // Canonical bytes = JSON with empty hash field.
        let canonical = serde_json::to_vec(&ev)?;
        let digest = crypto::hash::sha256(&canonical)?;
        ev.hash = hex::encode(digest);
        self.prev_hash = ev.hash.clone();

        let line = serde_json::to_string(&ev)?;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        writeln!(f, "{}", line)?;
        f.sync_all()?;
        Ok(())
    }
}

fn load_last_hash(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(GENESIS_HASH.to_string());
    }
    // TODO week 2: tail-read efficiently for large logs. For MVP, the file is
    // rotated daily so reading the whole file is fine.
    let contents = std::fs::read_to_string(path)?;
    let last = contents.lines().rev().find(|l| !l.trim().is_empty());
    match last {
        Some(line) => {
            let ev: Event = serde_json::from_str(line)?;
            Ok(ev.hash)
        }
        None => Ok(GENESIS_HASH.to_string()),
    }
}

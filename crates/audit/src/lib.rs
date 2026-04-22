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

    pub fn read_all(&self) -> Result<Vec<Event>> {
        read_all(&self.path)
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

/// Read all events from an audit log file, in chronological order (oldest first).
/// Returns an empty Vec if the file does not exist. Blank lines are skipped.
pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<Event>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = std::fs::read_to_string(path)?;
    let mut events = Vec::with_capacity(contents.lines().count());
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str::<Event>(line)?);
    }
    Ok(events)
}

#[derive(Debug, Clone)]
pub struct ChainVerification {
    pub valid: bool,
    /// Zero-based index of the first event that broke the chain, if any.
    pub break_at: Option<usize>,
    pub events_checked: usize,
}

/// Walk `events` (must be in chronological order) and verify each event's
/// `prev_hash` points at the preceding event's `hash`, and that each `hash`
/// is a correct SHA-256 of the event's canonical form (with `hash` cleared).
pub fn verify_chain(events: &[Event]) -> Result<ChainVerification> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (i, ev) in events.iter().enumerate() {
        if ev.prev_hash != expected_prev {
            return Ok(ChainVerification {
                valid: false,
                break_at: Some(i),
                events_checked: i,
            });
        }
        let mut check_ev = ev.clone();
        check_ev.hash = String::new();
        let canonical = serde_json::to_vec(&check_ev)?;
        let digest = crypto::hash::sha256(&canonical)?;
        let computed = hex::encode(digest);
        if computed != ev.hash {
            return Ok(ChainVerification {
                valid: false,
                break_at: Some(i),
                events_checked: i,
            });
        }
        expected_prev = ev.hash.clone();
    }
    Ok(ChainVerification {
        valid: true,
        break_at: None,
        events_checked: events.len(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_event(name: &str) -> Event {
        Event {
            ts: OffsetDateTime::UNIX_EPOCH,
            event: name.into(),
            actor: Actor {
                user_id: None,
                ip: "127.0.0.1".into(),
                ua: "test".into(),
            },
            target: serde_json::json!({}),
            outcome: Outcome::Success,
            meta: serde_json::json!({}),
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn write_read_verify_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.write(sample_event("auth.login")).unwrap();
        log.write(sample_event("share.created")).unwrap();
        log.write(sample_event("share.redeem")).unwrap();

        let events = read_all(&path).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event, "auth.login");
        assert_eq!(events[0].prev_hash, GENESIS_HASH);
        assert_eq!(events[1].prev_hash, events[0].hash);
        assert_eq!(events[2].prev_hash, events[1].hash);

        let v = verify_chain(&events).unwrap();
        assert!(v.valid);
        assert_eq!(v.events_checked, 3);
        assert!(v.break_at.is_none());
    }

    #[test]
    fn verify_detects_tampering() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.write(sample_event("a")).unwrap();
        log.write(sample_event("b")).unwrap();
        log.write(sample_event("c")).unwrap();

        let mut events = read_all(&path).unwrap();
        // Tamper with the middle event's meta — its stored hash no longer matches
        // the recomputed hash of the tampered content.
        events[1].meta = serde_json::json!({ "tampered": true });
        let v = verify_chain(&events).unwrap();
        assert!(!v.valid);
        assert_eq!(v.break_at, Some(1));
    }

    #[test]
    fn verify_detects_chain_break() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        let mut log = Log::open(&path).unwrap();
        log.write(sample_event("a")).unwrap();
        log.write(sample_event("b")).unwrap();

        let mut events = read_all(&path).unwrap();
        // Replace prev_hash with something that doesn't match event 0's hash.
        events[1].prev_hash = "0".repeat(64);
        let v = verify_chain(&events).unwrap();
        assert!(!v.valid);
        assert_eq!(v.break_at, Some(1));
    }
}

//! # storage
//!
//! SQLite for metadata (users, vendors, prints, shares, sessions) and a
//! directory of AES-GCM-encrypted files for the actual print contents.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub mod api_tokens;
pub mod prints;
pub mod sessions;
pub mod shares;
pub mod users;
pub mod vendors;

pub use api_tokens::{ApiToken, IssuedApiToken};
pub use prints::{Print, PrintStore};
pub use sessions::{IssuedSession, Session};
pub use shares::{Share, ShareListItem, ShareSecrets};
pub use users::{User, UserRole};
pub use vendors::Vendor;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Conflict,
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub struct Store {
    pub conn: Connection,
    pub blobs_dir: PathBuf,
}

impl Store {
    pub fn open(db_path: impl AsRef<Path>, blobs_dir: impl AsRef<Path>) -> Result<Self> {
        std::fs::create_dir_all(&blobs_dir)?;
        if let Some(parent) = db_path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path)?;
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))?;
        Ok(Self {
            conn,
            blobs_dir: blobs_dir.as_ref().to_path_buf(),
        })
    }
}

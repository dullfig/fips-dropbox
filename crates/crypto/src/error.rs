use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("CNG error: {0}")]
    Cng(#[from] cng::CngError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("invalid nonce length")]
    InvalidNonceLength,

    #[error("KEK file already exists at the target path")]
    KekAlreadyExists,

    #[error("decryption failed: tag mismatch or tampered data")]
    DecryptionFailed,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

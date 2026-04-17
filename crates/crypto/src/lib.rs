//! # crypto — the FIPS boundary
//!
//! This is the only non-[`cng`] crate in the workspace allowed to touch
//! cryptographic primitives. Every function here delegates to [`cng`], which
//! in turn delegates to the Windows Cryptographic Primitives Library
//! (CMVP cert #4339).
//!
//! ## Rule
//!
//! Never add an algorithm here that is not on the FIPS 140-3 Approved list.
//! Never add a dependency on another crypto library (`ring`, `rustls` default
//! provider, `RustCrypto`, `libsodium`, etc.).

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod kek;
pub mod mac;
pub mod rand;
pub mod token;

pub use error::{CryptoError, Result};
pub use kek::KekManager;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit symmetric key for per-blob AES-GCM. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey(pub(crate) [u8; 32]);

impl DataKey {
    pub fn generate() -> Result<Self> {
        let mut k = [0u8; 32];
        cng::random_bytes(&mut k)?;
        Ok(Self(k))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A [`DataKey`] encrypted under the machine KEK. Safe to persist beside ciphertext.
pub struct WrappedKey(pub Vec<u8>);

/// Fixed-size SHA-256 digest.
pub type Digest = [u8; 32];

/// Fixed-size HMAC-SHA-256 output.
pub type Mac = [u8; 32];

/// Startup check. Call once at service boot; refuse to run on failure.
pub fn assert_fips_mode() -> Result<()> {
    cng::assert_fips_mode().map_err(Into::into)
}

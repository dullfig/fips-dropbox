//! Key Encryption Key (KEK) management.
//!
//! The KEK is a 32-byte symmetric key, generated once at first service start,
//! protected at rest with DPAPI under machine scope, and held only in process
//! memory when the service is running. The KEK wraps per-blob Data Encryption
//! Keys (DEKs); it never itself encrypts CUI directly.
//!
//! Threat model:
//! - At-rest theft of `kek.bin` alone is not sufficient to recover the KEK;
//!   the attacker also needs DPAPI secrets bound to this machine.
//! - A compromised machine where an admin runs code as SYSTEM can unwrap the
//!   KEK — this is the same trust floor BitLocker and SQL TDE assume.
//!
//! Future v0.2: migrate wrapping to a TPM-bound key via NCryptCreatePersistedKey
//! with the Microsoft Platform Crypto Provider.

use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DataKey, Result};

const KEK_DPAPI_ENTROPY: &[u8] = b"fips-dropbox KEK v1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KekManager {
    kek: [u8; 32],
}

impl KekManager {
    /// Generate a fresh KEK and persist it under DPAPI machine scope.
    /// Refuses to overwrite an existing file — use [`KekManager::load`] instead.
    pub fn init(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            return Err(crate::CryptoError::KekAlreadyExists);
        }
        let mut kek = [0u8; 32];
        crate::rand::fill(&mut kek)?;
        let wrapped = cng::dpapi_protect_machine(&kek, KEK_DPAPI_ENTROPY)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &wrapped)?;
        Ok(Self { kek })
    }

    /// Load an existing KEK from disk, unwrapping with DPAPI.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let wrapped = std::fs::read(path)?;
        let raw = cng::dpapi_unprotect_machine(&wrapped, KEK_DPAPI_ENTROPY)?;
        if raw.len() != 32 {
            return Err(crate::CryptoError::InvalidKeyLength);
        }
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&raw);
        Ok(Self { kek })
    }

    /// Wrap a DEK with the KEK. Output layout: `[nonce(12) || tag(16) || ciphertext(32)]`.
    pub fn wrap_dek(&self, dek: &DataKey) -> Result<Vec<u8>> {
        let nonce = crate::rand::nonce_12()?;
        let (ct, tag) = cng::aes_256_gcm_encrypt(&self.kek, &nonce, &[], dek.as_bytes())?;
        let mut out = Vec::with_capacity(12 + 16 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap a DEK. Returns an error on tag mismatch.
    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<DataKey> {
        if wrapped.len() != 12 + 16 + 32 {
            return Err(crate::CryptoError::InvalidKeyLength);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&wrapped[0..12]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&wrapped[12..28]);
        let ct = &wrapped[28..60];
        let pt = cng::aes_256_gcm_decrypt(&self.kek, &nonce, &[], ct, &tag)?;
        if pt.len() != 32 {
            return Err(crate::CryptoError::InvalidKeyLength);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&pt);
        Ok(DataKey(dek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek.bin");

        let mgr = KekManager::init(&path).unwrap();
        let dek = DataKey::generate().unwrap();
        let wrapped = mgr.wrap_dek(&dek).unwrap();
        drop(mgr);

        let mgr2 = KekManager::load(&path).unwrap();
        let dek2 = mgr2.unwrap_dek(&wrapped).unwrap();
        assert_eq!(dek.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn init_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek.bin");
        KekManager::init(&path).unwrap();
        let r = KekManager::init(&path);
        assert!(matches!(r, Err(crate::CryptoError::KekAlreadyExists)));
    }

    #[test]
    fn tampered_wrapped_dek_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek.bin");
        let mgr = KekManager::init(&path).unwrap();
        let dek = DataKey::generate().unwrap();
        let mut wrapped = mgr.wrap_dek(&dek).unwrap();
        wrapped[30] ^= 0x01; // flip a bit in the ciphertext
        let r = mgr.unwrap_dek(&wrapped);
        assert!(r.is_err(), "tampered DEK should not unwrap");
    }
}

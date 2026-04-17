use crate::{DataKey, Result};

/// An AES-256-GCM ciphertext bundle. Store all three fields beside the blob
/// (or embed in a fixed-length header prefix).
pub struct Sealed {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

/// Encrypt `plaintext` under `key`. A fresh nonce is generated internally.
///
/// `aad` (Additional Authenticated Data) binds the ciphertext to its
/// metadata context — e.g., `print_id || vendor_id || uploader_id`. An
/// attacker who swaps ciphertext across rows will cause decryption to fail.
pub fn seal(key: &DataKey, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let nonce = crate::rand::nonce_12()?;
    let (ciphertext, tag) = cng::aes_256_gcm_encrypt(key.as_bytes(), &nonce, aad, plaintext)?;
    Ok(Sealed { nonce, ciphertext, tag })
}

/// Decrypt. Returns `Err(DecryptionFailed)` if the tag does not verify.
pub fn open(key: &DataKey, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>> {
    Ok(cng::aes_256_gcm_decrypt(
        key.as_bytes(),
        &sealed.nonce,
        aad,
        &sealed.ciphertext,
        &sealed.tag,
    )?)
}

// TODO week 2: streaming seal/open for multi-GB print files — chunked GCM
// with per-chunk counter, or CTR+HMAC-SHA-256 construction reviewed against
// NIST SP 800-38D guidance on nonce reuse and chunk boundaries.

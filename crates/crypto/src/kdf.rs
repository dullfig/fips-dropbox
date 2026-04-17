use crate::Result;

/// OWASP 2023 recommended minimum iteration count for PBKDF2-HMAC-SHA-256.
pub const PBKDF2_MIN_ITERATIONS: u64 = 600_000;

/// Derive a 32-byte key from a password and salt using PBKDF2-HMAC-SHA-256.
///
/// `iterations` must be >= [`PBKDF2_MIN_ITERATIONS`].
pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: u64) -> Result<[u8; 32]> {
    debug_assert!(iterations >= PBKDF2_MIN_ITERATIONS);
    let out = cng::pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

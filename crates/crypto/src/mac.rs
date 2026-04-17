use crate::{Mac, Result};

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Mac> {
    Ok(cng::hmac_sha256(key, data)?)
}

/// Verify HMAC-SHA-256 with constant-time comparison.
pub fn verify(key: &[u8], data: &[u8], tag: &Mac) -> Result<bool> {
    let expected = hmac_sha256(key, data)?;
    Ok(constant_time_eq(&expected, tag))
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

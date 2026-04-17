use crate::Result;

/// Fill `buf` with random bytes from a FIPS-approved DRBG.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    cng::random_bytes(buf)?;
    Ok(())
}

/// Allocate and fill `n` random bytes.
pub fn bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    fill(&mut v)?;
    Ok(v)
}

/// A fresh 12-byte nonce (for AES-GCM).
pub fn nonce_12() -> Result<[u8; 12]> {
    let mut n = [0u8; 12];
    fill(&mut n)?;
    Ok(n)
}

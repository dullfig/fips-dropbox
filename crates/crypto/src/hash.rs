use crate::{Digest, Result};
use std::io::Read;

/// Single-shot SHA-256.
pub fn sha256(data: &[u8]) -> Result<Digest> {
    Ok(cng::sha256(data)?)
}

/// Streaming SHA-256 for large files. Reads until EOF.
///
/// TODO: replace the allocating helper with true streaming via
/// BCryptCreateHash / BCryptHashData / BCryptFinishHash once cng exposes it.
pub fn sha256_stream<R: Read>(mut reader: R) -> Result<Digest> {
    let mut buf = Vec::with_capacity(64 * 1024);
    reader.read_to_end(&mut buf).map_err(|_| crate::CryptoError::InvalidKeyLength)?;
    sha256(&buf)
}

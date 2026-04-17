//! URL-safe tokens for share links and human-readable access codes.

use crate::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Random URL-safe token for share URLs. 16 bytes of entropy = 128 bits.
pub fn url_token() -> Result<String> {
    let raw = crate::rand::bytes(16)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Human-readable access code. 15 chars, grouped as AAA-BBB-CCC-DDD.
/// ~75 bits of entropy from an unambiguous alphabet (no 0/O/1/I/L).
pub fn access_code() -> Result<String> {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let raw = crate::rand::bytes(15)?;
    let mut out = String::with_capacity(19);
    for (i, b) in raw.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push('-');
        }
        out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
    }
    Ok(out)
}

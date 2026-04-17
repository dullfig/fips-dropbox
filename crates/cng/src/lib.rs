//! # cng
//!
//! The one and only crate in this workspace that calls into native
//! cryptographic primitives. Everything here maps to a specific `BCrypt*` or
//! `NCrypt*` function in the Windows Cryptographic Primitives Library
//! (CMVP cert #4339 at time of writing).
//!
//! By keeping this surface narrow, the System Security Plan (SSP) can point
//! at a single crate as the sole FIPS-inheritance boundary. Every other
//! crate in the workspace MUST go through [`crypto`](../crypto/index.html).
//!
//! ## Rule
//!
//! Do not add algorithms here that are not on the FIPS 140-3 Approved list.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use thiserror::Error;
use windows_sys::Win32::Foundation::{BOOLEAN, GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::*;

const BCRYPT_INIT_AUTH_MODE_INFO_VERSION: u32 = 1;
const STATUS_AUTH_TAG_MISMATCH: u32 = 0xC000_A002;

#[derive(Debug, Error)]
pub enum CngError {
    #[error("CNG returned NTSTATUS 0x{0:08x}")]
    Status(u32),
    #[error("Win32 error {0}")]
    WinError(u32),
    #[error("authentication tag mismatch (decryption failure)")]
    AuthTagMismatch,
    #[error("FIPS mode is not enabled on this host")]
    FipsModeDisabled,
    #[error("unsupported parameter length (expected {expected}, got {got})")]
    UnsupportedLength { expected: usize, got: usize },
}

pub type Result<T> = std::result::Result<T, CngError>;

#[inline]
fn check(status: i32) -> Result<()> {
    if status >= 0 {
        Ok(())
    } else {
        Err(CngError::Status(status as u32))
    }
}

// ---------------------------------------------------------------------------
// RAII handles
// ---------------------------------------------------------------------------

struct AlgHandle(BCRYPT_ALG_HANDLE);
impl Drop for AlgHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
}

struct KeyHandle(BCRYPT_KEY_HANDLE);
impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyKey(self.0);
            }
        }
    }
}

/// Length in bytes of a NUL-terminated wide string, including the NUL.
///
/// # Safety
/// `p` must point to a NUL-terminated sequence of `u16` values.
unsafe fn wstrlen_bytes_incl_nul(p: *const u16) -> u32 {
    let mut n: u32 = 0;
    unsafe {
        while *p.add(n as usize) != 0 {
            n += 1;
        }
    }
    (n + 1) * 2
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------

/// Fill `buf` with random bytes from BCryptGenRandom using the system-preferred
/// DRBG. When FIPS mode is enabled on the host, this is a FIPS-approved DRBG.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    check(status)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Single-shot SHA-256.
pub fn sha256(data: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let status = unsafe {
        BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE,
            std::ptr::null_mut(),
            0,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        )
    };
    check(status)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// MAC
// ---------------------------------------------------------------------------

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let status = unsafe {
        BCryptHash(
            BCRYPT_HMAC_SHA256_ALG_HANDLE,
            key.as_ptr() as *mut u8,
            key.len() as u32,
            data.as_ptr() as *mut u8,
            data.len() as u32,
            out.as_mut_ptr(),
            out.len() as u32,
        )
    };
    check(status)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// AEAD — AES-256-GCM
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt. Returns (ciphertext, 16-byte tag).
///
/// `aad` (Additional Authenticated Data) is cryptographically bound to the
/// ciphertext but not encrypted. Use it to bind metadata like print_id.
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16])> {
    let alg = open_aes_gcm()?;
    let sym = generate_aes_key(alg.0, key)?;

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; 16];
    let mut written: u32 = 0;

    let status = unsafe {
        let mut mode_info = auth_mode_info(nonce, aad, tag.as_mut_ptr(), tag.len() as u32);
        BCryptEncrypt(
            sym.0,
            if plaintext.is_empty() {
                std::ptr::null_mut()
            } else {
                plaintext.as_ptr() as *mut u8
            },
            plaintext.len() as u32,
            &mut mode_info as *mut _ as *mut std::ffi::c_void,
            std::ptr::null_mut(),
            0,
            if ciphertext.is_empty() {
                std::ptr::null_mut()
            } else {
                ciphertext.as_mut_ptr()
            },
            ciphertext.len() as u32,
            &mut written,
            0,
        )
    };
    check(status)?;
    ciphertext.truncate(written as usize);
    Ok((ciphertext, tag))
}

/// AES-256-GCM decrypt. Returns `Err(AuthTagMismatch)` if the tag fails to verify.
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    let alg = open_aes_gcm()?;
    let sym = generate_aes_key(alg.0, key)?;

    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut written: u32 = 0;
    let mut tag_copy = *tag;

    let status = unsafe {
        let mut mode_info =
            auth_mode_info(nonce, aad, tag_copy.as_mut_ptr(), tag_copy.len() as u32);
        BCryptDecrypt(
            sym.0,
            if ciphertext.is_empty() {
                std::ptr::null_mut()
            } else {
                ciphertext.as_ptr() as *mut u8
            },
            ciphertext.len() as u32,
            &mut mode_info as *mut _ as *mut std::ffi::c_void,
            std::ptr::null_mut(),
            0,
            if plaintext.is_empty() {
                std::ptr::null_mut()
            } else {
                plaintext.as_mut_ptr()
            },
            plaintext.len() as u32,
            &mut written,
            0,
        )
    };
    if status as u32 == STATUS_AUTH_TAG_MISMATCH {
        return Err(CngError::AuthTagMismatch);
    }
    check(status)?;
    plaintext.truncate(written as usize);
    Ok(plaintext)
}

fn open_aes_gcm() -> Result<AlgHandle> {
    let mut h: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut h, BCRYPT_AES_ALGORITHM, std::ptr::null(), 0)
    };
    check(status)?;
    let handle = AlgHandle(h);

    let len = unsafe { wstrlen_bytes_incl_nul(BCRYPT_CHAIN_MODE_GCM) };
    let status = unsafe {
        BCryptSetProperty(
            h as *mut _,
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAIN_MODE_GCM as *const u8,
            len,
            0,
        )
    };
    check(status)?;
    Ok(handle)
}

fn generate_aes_key(alg: BCRYPT_ALG_HANDLE, key_bytes: &[u8]) -> Result<KeyHandle> {
    let mut h: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let status = unsafe {
        BCryptGenerateSymmetricKey(
            alg,
            &mut h,
            std::ptr::null_mut(),
            0,
            key_bytes.as_ptr() as *mut u8,
            key_bytes.len() as u32,
            0,
        )
    };
    check(status)?;
    Ok(KeyHandle(h))
}

/// # Safety
/// `tag_ptr` must be valid for reads/writes of `tag_len` bytes for the
/// lifetime of any BCryptEncrypt/BCryptDecrypt call using the returned struct.
unsafe fn auth_mode_info(
    nonce: &[u8; 12],
    aad: &[u8],
    tag_ptr: *mut u8,
    tag_len: u32,
) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: BCRYPT_INIT_AUTH_MODE_INFO_VERSION,
        pbNonce: nonce.as_ptr() as *mut u8,
        cbNonce: nonce.len() as u32,
        pbAuthData: if aad.is_empty() {
            std::ptr::null_mut()
        } else {
            aad.as_ptr() as *mut u8
        },
        cbAuthData: aad.len() as u32,
        pbTag: tag_ptr,
        cbTag: tag_len,
        pbMacContext: std::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD: 0,
        cbData: 0,
        dwFlags: 0,
    }
}

// ---------------------------------------------------------------------------
// KDF — PBKDF2-HMAC-SHA-256
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA-256. OWASP 2023 recommends >= 600_000 iterations for CUI.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    out_len: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            BCRYPT_HMAC_SHA256_ALG_HANDLE,
            password.as_ptr() as *mut u8,
            password.len() as u32,
            salt.as_ptr() as *mut u8,
            salt.len() as u32,
            iterations,
            out.as_mut_ptr(),
            out.len() as u32,
            0,
        )
    };
    check(status)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// FIPS mode
// ---------------------------------------------------------------------------

/// Returns `Ok(())` iff the host has the "System cryptography: Use FIPS
/// compliant algorithms" policy enabled. Call once at service boot and refuse
/// to run otherwise.
pub fn assert_fips_mode() -> Result<()> {
    let mut enabled: BOOLEAN = 0;
    let status = unsafe { BCryptGetFipsAlgorithmMode(&mut enabled) };
    check(status)?;
    if enabled != 0 {
        Ok(())
    } else {
        Err(CngError::FipsModeDisabled)
    }
}

// ---------------------------------------------------------------------------
// DPAPI — machine-scoped protect/unprotect
// ---------------------------------------------------------------------------
//
// Used to seal the master KEK at rest. When the host is in FIPS mode, DPAPI
// performs all cryptographic operations via the same FIPS-validated CNG
// module as the rest of this crate.
//
// Scope: CRYPTPROTECT_LOCAL_MACHINE ties the key to the machine, not to a
// specific user profile, so the Windows service can decrypt on startup
// regardless of which account it runs under.

fn last_win_error() -> CngError {
    let code = unsafe { GetLastError() };
    CngError::WinError(code)
}

/// Encrypt `plaintext` with the machine's DPAPI master key. `entropy` is
/// mixed in as an app-specific salt — pass the same bytes on unprotect.
pub fn dpapi_protect_machine(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut in_blob,
            std::ptr::null(),
            &mut entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(last_win_error());
    }

    let result = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(result)
}

/// Decrypt a DPAPI-protected blob. `entropy` must match the value passed to
/// [`dpapi_protect_machine`].
pub fn dpapi_unprotect_machine(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            std::ptr::null_mut(),
            &mut entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(last_win_error());
    }

    let result = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests — known-answer vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 SHA-256 KAT for "abc".
    const SHA256_ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    #[test]
    fn sha256_kat_abc() {
        assert_eq!(sha256(b"abc").unwrap(), SHA256_ABC);
    }

    #[test]
    fn random_bytes_nonzero_and_distinct() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    // RFC 4231 test case 1 for HMAC-SHA-256.
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(hmac_sha256(&key, data).unwrap(), expected);
    }

    // McGrew & Viega "The Galois/Counter Mode of Operation (GCM)" Test Case 14.
    // AES-256, 16-byte all-zero plaintext, all-zero key and IV, empty AAD.
    #[test]
    fn aes_256_gcm_mcgrew_case14() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let aad: &[u8] = &[];
        let expected_ct: [u8; 16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let expected_tag: [u8; 16] = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];
        let (ct, tag) = aes_256_gcm_encrypt(&key, &nonce, aad, &plaintext).unwrap();
        assert_eq!(ct.as_slice(), expected_ct.as_slice());
        assert_eq!(tag, expected_tag);

        let pt = aes_256_gcm_decrypt(&key, &nonce, aad, &ct, &tag).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    // McGrew & Viega Test Case 16 — AES-256 with AAD and a longer plaintext.
    #[test]
    fn aes_256_gcm_mcgrew_case16() {
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let expected_ct: [u8; 60] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
            0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
            0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
            0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];
        let expected_tag: [u8; 16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
            0x55, 0x1b,
        ];
        let (ct, tag) = aes_256_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
        assert_eq!(ct.as_slice(), expected_ct.as_slice());
        assert_eq!(tag, expected_tag);

        let pt = aes_256_gcm_decrypt(&key, &nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    // Tag-tamper detection.
    #[test]
    fn aes_256_gcm_bad_tag_rejected() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let (ct, mut tag) = aes_256_gcm_encrypt(&key, &nonce, &[], b"hello world").unwrap();
        tag[0] ^= 0x01;
        match aes_256_gcm_decrypt(&key, &nonce, &[], &ct, &tag) {
            Err(CngError::AuthTagMismatch) => (),
            other => panic!("expected AuthTagMismatch, got {:?}", other),
        }
    }

    // PBKDF2-HMAC-SHA-256 vectors (widely published; computable via
    // `hashlib.pbkdf2_hmac('sha256', ...)` in Python).
    #[test]
    fn pbkdf2_sha256_password_salt_1() {
        let out = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32).unwrap();
        let expected: [u8; 32] = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    #[test]
    fn pbkdf2_sha256_password_salt_4096() {
        let out = pbkdf2_hmac_sha256(b"password", b"salt", 4096, 32).unwrap();
        let expected: [u8; 32] = [
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
            0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73,
            0xaa, 0x98, 0x13, 0x4a,
        ];
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    // On a non-FIPS host (our dev box) this should return FipsModeDisabled.
    // On the FIPS VM it should return Ok(()). We only assert the call returns.
    #[test]
    fn assert_fips_mode_returns() {
        let _ = assert_fips_mode();
    }

    #[test]
    fn dpapi_round_trip() {
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let entropy = b"fips-dropbox KEK v1";
        let ct = dpapi_protect_machine(plaintext, entropy).unwrap();
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        let pt = dpapi_unprotect_machine(&ct, entropy).unwrap();
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn dpapi_wrong_entropy_fails() {
        let ct = dpapi_protect_machine(b"secret", b"correct entropy").unwrap();
        let r = dpapi_unprotect_machine(&ct, b"wrong entropy");
        assert!(r.is_err(), "unprotect with wrong entropy should fail");
    }
}

//! Users: admins and vendor accounts.
//!
//! Password hashes are stored as PBKDF2-HMAC-SHA-256 output (32 bytes) with a
//! per-user random salt (16 bytes) and a per-user iteration count (so a future
//! bump from 600k → 1.2M rehashes gradually on each user login).

use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, StorageError};

const PBKDF2_ITERATIONS: u64 = crypto::kdf::PBKDF2_MIN_ITERATIONS;
const SALT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    Vendor,
}

impl UserRole {
    fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::Vendor => "vendor",
        }
    }
    fn parse(s: &str) -> Option<UserRole> {
        match s {
            "admin" => Some(UserRole::Admin),
            "vendor" => Some(UserRole::Vendor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub created_at: OffsetDateTime,
    pub disabled_at: Option<OffsetDateTime>,
    pub totp_secret_wrapped: Option<Vec<u8>>,
    // Auth material is crate-private so callers can't accidentally log it.
    password_hash: Vec<u8>,
    password_salt: Vec<u8>,
    password_iters: u64,
}

/// Create a user with the given role. Returns [`StorageError::Conflict`] on
/// duplicate email.
pub fn create(conn: &Connection, email: &str, role: UserRole, password: &str) -> Result<User> {
    let id = Uuid::now_v7();
    let salt = crypto::rand::bytes(SALT_LEN)?;
    let hash = crypto::kdf::derive_key_from_password(password, &salt, PBKDF2_ITERATIONS)?;
    let now = OffsetDateTime::now_utc();
    let now_ms = dt_to_millis(now);

    conn.execute(
        "INSERT INTO users
         (id, email, role, password_hash, password_salt, password_iters,
          totp_secret_wrapped, created_at, disabled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL)",
        params![
            id.as_bytes().as_slice(),
            email,
            role.as_str(),
            hash.as_slice(),
            salt.as_slice(),
            PBKDF2_ITERATIONS as i64,
            now_ms,
        ],
    )
    .map_err(map_conflict)?;

    Ok(User {
        id,
        email: email.to_string(),
        role,
        created_at: now,
        disabled_at: None,
        totp_secret_wrapped: None,
        password_hash: hash.to_vec(),
        password_salt: salt,
        password_iters: PBKDF2_ITERATIONS,
    })
}

pub fn find_by_email(conn: &Connection, email: &str) -> Result<Option<User>> {
    conn.query_row(
        "SELECT id, email, role, password_hash, password_salt, password_iters,
                totp_secret_wrapped, created_at, disabled_at
         FROM users WHERE email = ?1",
        params![email],
        row_to_user,
    )
    .optional()
    .map_err(Into::into)
}

pub fn find_by_id(conn: &Connection, id: &Uuid) -> Result<Option<User>> {
    conn.query_row(
        "SELECT id, email, role, password_hash, password_salt, password_iters,
                totp_secret_wrapped, created_at, disabled_at
         FROM users WHERE id = ?1",
        params![id.as_bytes().as_slice()],
        row_to_user,
    )
    .optional()
    .map_err(Into::into)
}

/// Verify a candidate password. Returns `Some(user)` on success, `None` if the
/// user does not exist, is disabled, or the password is wrong.
///
/// When the user does not exist we still run PBKDF2 once to blunt timing
/// oracles that would otherwise reveal account existence.
pub fn verify_password(
    conn: &Connection,
    email: &str,
    password: &str,
) -> Result<Option<User>> {
    let user = match find_by_email(conn, email)? {
        Some(u) => u,
        None => {
            let _ = crypto::kdf::derive_key_from_password(
                password,
                &[0u8; SALT_LEN],
                PBKDF2_ITERATIONS,
            )?;
            return Ok(None);
        }
    };
    if user.disabled_at.is_some() {
        return Ok(None);
    }
    let candidate = crypto::kdf::derive_key_from_password(
        password,
        &user.password_salt,
        user.password_iters,
    )?;
    if constant_time_eq(&candidate, &user.password_hash) {
        Ok(Some(user))
    } else {
        Ok(None)
    }
}

pub fn rotate_password(conn: &Connection, id: &Uuid, new_password: &str) -> Result<()> {
    let salt = crypto::rand::bytes(SALT_LEN)?;
    let hash =
        crypto::kdf::derive_key_from_password(new_password, &salt, PBKDF2_ITERATIONS)?;
    let affected = conn.execute(
        "UPDATE users SET password_hash = ?1, password_salt = ?2, password_iters = ?3
         WHERE id = ?4",
        params![
            hash.as_slice(),
            salt.as_slice(),
            PBKDF2_ITERATIONS as i64,
            id.as_bytes().as_slice(),
        ],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

pub fn disable(conn: &Connection, id: &Uuid) -> Result<()> {
    let now_ms = dt_to_millis(OffsetDateTime::now_utc());
    let affected = conn.execute(
        "UPDATE users SET disabled_at = ?1 WHERE id = ?2 AND disabled_at IS NULL",
        params![now_ms, id.as_bytes().as_slice()],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

pub fn enable(conn: &Connection, id: &Uuid) -> Result<()> {
    let affected = conn.execute(
        "UPDATE users SET disabled_at = NULL WHERE id = ?1",
        params![id.as_bytes().as_slice()],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let id_blob: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })?;
    let email: String = row.get(1)?;
    let role_str: String = row.get(2)?;
    let role = UserRole::parse(&role_str).ok_or_else(|| {
        rusqlite::Error::InvalidColumnType(2, "role".into(), rusqlite::types::Type::Text)
    })?;
    let password_hash: Vec<u8> = row.get(3)?;
    let password_salt: Vec<u8> = row.get(4)?;
    let password_iters: i64 = row.get(5)?;
    let totp_secret_wrapped: Option<Vec<u8>> = row.get(6)?;
    let created_at_ms: i64 = row.get(7)?;
    let disabled_at_ms: Option<i64> = row.get(8)?;

    Ok(User {
        id,
        email,
        role,
        created_at: millis_to_dt(created_at_ms),
        disabled_at: disabled_at_ms.map(millis_to_dt),
        totp_secret_wrapped,
        password_hash,
        password_salt,
        password_iters: password_iters as u64,
    })
}

fn map_conflict(e: rusqlite::Error) -> StorageError {
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == rusqlite::ErrorCode::ConstraintViolation {
            return StorageError::Conflict;
        }
    }
    StorageError::Sqlite(e)
}

fn dt_to_millis(dt: OffsetDateTime) -> i64 {
    (dt.unix_timestamp_nanos() / 1_000_000) as i64
}

fn millis_to_dt(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let conn = Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))
            .unwrap();
        (dir, conn)
    }

    #[test]
    fn create_and_find() {
        let (_d, conn) = fresh_db();
        let u = create(&conn, "dan@example.com", UserRole::Admin, "hunter2hunter2").unwrap();
        assert_eq!(u.role, UserRole::Admin);
        let f = find_by_email(&conn, "dan@example.com").unwrap().unwrap();
        assert_eq!(f.id, u.id);
        let f2 = find_by_id(&conn, &u.id).unwrap().unwrap();
        assert_eq!(f2.email, "dan@example.com");
    }

    #[test]
    fn duplicate_email_is_conflict() {
        let (_d, conn) = fresh_db();
        create(&conn, "dan@example.com", UserRole::Admin, "pw1234567").unwrap();
        let r = create(&conn, "dan@example.com", UserRole::Vendor, "pw1234567");
        assert!(matches!(r, Err(StorageError::Conflict)));
    }

    #[test]
    fn verify_password_succeeds_and_fails() {
        let (_d, conn) = fresh_db();
        create(&conn, "dan@example.com", UserRole::Admin, "correct-horse-battery-staple")
            .unwrap();
        let good =
            verify_password(&conn, "dan@example.com", "correct-horse-battery-staple").unwrap();
        assert!(good.is_some(), "correct password should verify");
        let bad = verify_password(&conn, "dan@example.com", "wrong").unwrap();
        assert!(bad.is_none());
        let missing = verify_password(&conn, "nobody@example.com", "whatever").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn rotate_password_works() {
        let (_d, conn) = fresh_db();
        let u = create(&conn, "dan@example.com", UserRole::Admin, "old-password").unwrap();
        rotate_password(&conn, &u.id, "new-password-longer").unwrap();
        assert!(verify_password(&conn, "dan@example.com", "old-password")
            .unwrap()
            .is_none());
        assert!(verify_password(&conn, "dan@example.com", "new-password-longer")
            .unwrap()
            .is_some());
    }

    #[test]
    fn disable_blocks_login() {
        let (_d, conn) = fresh_db();
        let u = create(&conn, "dan@example.com", UserRole::Admin, "pw1234567").unwrap();
        assert!(verify_password(&conn, "dan@example.com", "pw1234567")
            .unwrap()
            .is_some());
        disable(&conn, &u.id).unwrap();
        assert!(verify_password(&conn, "dan@example.com", "pw1234567")
            .unwrap()
            .is_none());
        enable(&conn, &u.id).unwrap();
        assert!(verify_password(&conn, "dan@example.com", "pw1234567")
            .unwrap()
            .is_some());
    }
}

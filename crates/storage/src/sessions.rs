//! Admin sessions (cookie-based).
//!
//! The cookie value is a random 32-byte URL-safe-base64 string. Only its
//! SHA-256 hash is persisted, so a database leak reveals nothing an attacker
//! could replay. CSRF tokens are generated per session and embedded in
//! templates for form submission.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::Result;

pub const DEFAULT_TTL_HOURS: i64 = 12;

#[derive(Debug, Clone)]
pub struct Session {
    pub id_hash: [u8; 32],
    pub user_id: Uuid,
    pub csrf_token: [u8; 32],
    pub ip: String,
    pub user_agent: String,
    pub expires_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
}

pub struct IssuedSession {
    pub session: Session,
    /// Returned once; caller sets as a Secure+HttpOnly cookie.
    pub raw_token: String,
}

pub fn create(
    conn: &Connection,
    user_id: &Uuid,
    ip: &str,
    ua: &str,
    ttl_hours: i64,
) -> Result<IssuedSession> {
    let raw_bytes = crypto::rand::bytes(32)?;
    let raw_token = URL_SAFE_NO_PAD.encode(&raw_bytes);
    let id_hash = crypto::hash::sha256(raw_token.as_bytes())?;

    let csrf_vec = crypto::rand::bytes(32)?;
    let mut csrf = [0u8; 32];
    csrf.copy_from_slice(&csrf_vec);

    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::hours(ttl_hours);

    conn.execute(
        "INSERT INTO sessions
         (id, user_id, csrf_token, ip, user_agent, expires_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id_hash.as_slice(),
            user_id.as_bytes().as_slice(),
            csrf.as_slice(),
            ip,
            ua,
            dt_to_millis(expires_at),
            dt_to_millis(now),
        ],
    )?;

    Ok(IssuedSession {
        session: Session {
            id_hash,
            user_id: *user_id,
            csrf_token: csrf,
            ip: ip.to_string(),
            user_agent: ua.to_string(),
            expires_at,
            last_seen_at: now,
        },
        raw_token,
    })
}

/// Look up by raw cookie value. Returns `None` if the session does not exist
/// or has expired. Updates `last_seen_at` on success.
pub fn find_valid(conn: &Connection, raw_token: &str) -> Result<Option<Session>> {
    let id_hash = crypto::hash::sha256(raw_token.as_bytes())?;
    let now_ms = dt_to_millis(OffsetDateTime::now_utc());
    let session = conn
        .query_row(
            "SELECT id, user_id, csrf_token, ip, user_agent, expires_at, last_seen_at
             FROM sessions WHERE id = ?1 AND expires_at > ?2",
            params![id_hash.as_slice(), now_ms],
            row_to_session,
        )
        .optional()?;
    if let Some(ref s) = session {
        conn.execute(
            "UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2",
            params![now_ms, s.id_hash.as_slice()],
        )?;
    }
    Ok(session)
}

pub fn revoke(conn: &Connection, raw_token: &str) -> Result<()> {
    let id_hash = crypto::hash::sha256(raw_token.as_bytes())?;
    conn.execute(
        "DELETE FROM sessions WHERE id = ?1",
        params![id_hash.as_slice()],
    )?;
    Ok(())
}

pub fn revoke_all_for_user(conn: &Connection, user_id: &Uuid) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1",
        params![user_id.as_bytes().as_slice()],
    )?)
}

pub fn purge_expired(conn: &Connection) -> Result<usize> {
    let now = dt_to_millis(OffsetDateTime::now_utc());
    Ok(conn.execute(
        "DELETE FROM sessions WHERE expires_at < ?1",
        params![now],
    )?)
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let id_vec: Vec<u8> = row.get(0)?;
    if id_vec.len() != 32 {
        return Err(rusqlite::Error::InvalidColumnType(
            0,
            "id".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    let mut id_hash = [0u8; 32];
    id_hash.copy_from_slice(&id_vec);

    let user_id_vec: Vec<u8> = row.get(1)?;
    let user_id = Uuid::from_slice(&user_id_vec).map_err(|_| {
        rusqlite::Error::InvalidColumnType(1, "user_id".into(), rusqlite::types::Type::Blob)
    })?;

    let csrf_vec: Vec<u8> = row.get(2)?;
    if csrf_vec.len() != 32 {
        return Err(rusqlite::Error::InvalidColumnType(
            2,
            "csrf_token".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    let mut csrf_token = [0u8; 32];
    csrf_token.copy_from_slice(&csrf_vec);

    let expires_at_ms: i64 = row.get(5)?;
    let last_seen_at_ms: i64 = row.get(6)?;

    Ok(Session {
        id_hash,
        user_id,
        csrf_token,
        ip: row.get(3)?,
        user_agent: row.get(4)?,
        expires_at: millis_to_dt(expires_at_ms),
        last_seen_at: millis_to_dt(last_seen_at_ms),
    })
}

fn dt_to_millis(dt: OffsetDateTime) -> i64 {
    (dt.unix_timestamp_nanos() / 1_000_000) as i64
}

fn millis_to_dt(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users;
    use tempfile::TempDir;

    fn scaffold() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))
            .unwrap();
        let u = users::create(&conn, "a@example.com", users::UserRole::Admin, "pw1234567").unwrap();
        (dir, conn, u.id)
    }

    #[test]
    fn issue_and_validate() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "127.0.0.1", "test/1.0", DEFAULT_TTL_HOURS).unwrap();
        assert!(!issued.raw_token.is_empty());
        let found = find_valid(&conn, &issued.raw_token).unwrap().unwrap();
        assert_eq!(found.user_id, user);
        assert_eq!(found.ip, "127.0.0.1");
    }

    #[test]
    fn wrong_token_returns_none() {
        let (_d, conn, user) = scaffold();
        create(&conn, &user, "127.0.0.1", "ua", DEFAULT_TTL_HOURS).unwrap();
        let not_found = find_valid(&conn, "totally-different-token").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn expired_session_returns_none() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "127.0.0.1", "ua", -1).unwrap();
        let r = find_valid(&conn, &issued.raw_token).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn revoke_immediately_invalidates() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "127.0.0.1", "ua", DEFAULT_TTL_HOURS).unwrap();
        revoke(&conn, &issued.raw_token).unwrap();
        assert!(find_valid(&conn, &issued.raw_token).unwrap().is_none());
    }

    #[test]
    fn revoke_all_for_user_works() {
        let (_d, conn, user) = scaffold();
        create(&conn, &user, "1.2.3.4", "a", DEFAULT_TTL_HOURS).unwrap();
        create(&conn, &user, "5.6.7.8", "b", DEFAULT_TTL_HOURS).unwrap();
        create(&conn, &user, "9.0.1.2", "c", DEFAULT_TTL_HOURS).unwrap();
        assert_eq!(revoke_all_for_user(&conn, &user).unwrap(), 3);
    }
}

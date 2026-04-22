//! Per-workstation API tokens used by the tray agent.
//!
//! Raw format: `fdbx_` + URL-safe-base64 of 32 random bytes (~48 chars total).
//! Only `sha256(full_token)` is persisted.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, StorageError};

pub const TOKEN_PREFIX: &str = "fdbx_";

#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub label: String,
    pub token_hash: [u8; 32],
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

pub struct IssuedApiToken {
    pub token: ApiToken,
    /// Returned once to the caller for display. Never stored in plaintext.
    pub raw_token: String,
}

pub fn create(conn: &Connection, user_id: &Uuid, label: &str) -> Result<IssuedApiToken> {
    let raw_bytes = crypto::rand::bytes(32)?;
    let raw_token = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(&raw_bytes));
    let token_hash = crypto::hash::sha256(raw_token.as_bytes())?;
    let id = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();

    conn.execute(
        "INSERT INTO api_tokens (id, user_id, label, token_hash, created_at, last_seen_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
        params![
            id.as_bytes().as_slice(),
            user_id.as_bytes().as_slice(),
            label,
            token_hash.as_slice(),
            dt_to_millis(now),
        ],
    )?;

    Ok(IssuedApiToken {
        token: ApiToken {
            id,
            user_id: *user_id,
            label: label.to_string(),
            token_hash,
            created_at: now,
            last_seen_at: None,
            revoked_at: None,
        },
        raw_token,
    })
}

/// Look up a token by raw value. Returns `None` if not found or revoked.
/// Updates `last_seen_at` on every successful lookup.
pub fn find_valid_by_raw(conn: &Connection, raw_token: &str) -> Result<Option<ApiToken>> {
    if !raw_token.starts_with(TOKEN_PREFIX) {
        return Ok(None);
    }
    let token_hash = crypto::hash::sha256(raw_token.as_bytes())?;
    let now = OffsetDateTime::now_utc();
    let found = conn
        .query_row(
            "SELECT id, user_id, label, token_hash, created_at, last_seen_at, revoked_at
             FROM api_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
            params![token_hash.as_slice()],
            row_to_token,
        )
        .optional()?;
    if let Some(ref t) = found {
        conn.execute(
            "UPDATE api_tokens SET last_seen_at = ?1 WHERE id = ?2",
            params![dt_to_millis(now), t.id.as_bytes().as_slice()],
        )?;
    }
    Ok(found)
}

pub fn list_for_user(conn: &Connection, user_id: &Uuid) -> Result<Vec<ApiToken>> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id, label, token_hash, created_at, last_seen_at, revoked_at
         FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![user_id.as_bytes().as_slice()], row_to_token)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn revoke(conn: &Connection, id: &Uuid) -> Result<()> {
    let now = dt_to_millis(OffsetDateTime::now_utc());
    let affected = conn.execute(
        "UPDATE api_tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        params![now, id.as_bytes().as_slice()],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

fn row_to_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiToken> {
    let id_blob: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })?;
    let user_blob: Vec<u8> = row.get(1)?;
    let user_id = Uuid::from_slice(&user_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(1, "user_id".into(), rusqlite::types::Type::Blob)
    })?;
    let hash_vec: Vec<u8> = row.get(3)?;
    if hash_vec.len() != 32 {
        return Err(rusqlite::Error::InvalidColumnType(
            3,
            "token_hash".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    let mut token_hash = [0u8; 32];
    token_hash.copy_from_slice(&hash_vec);

    let created_at_ms: i64 = row.get(4)?;
    let last_seen_at_ms: Option<i64> = row.get(5)?;
    let revoked_at_ms: Option<i64> = row.get(6)?;

    Ok(ApiToken {
        id,
        user_id,
        label: row.get(2)?,
        token_hash,
        created_at: millis_to_dt(created_at_ms),
        last_seen_at: last_seen_at_ms.map(millis_to_dt),
        revoked_at: revoked_at_ms.map(millis_to_dt),
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
    fn mint_and_verify() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "Dan's desktop").unwrap();
        assert!(issued.raw_token.starts_with(TOKEN_PREFIX));
        assert!(issued.raw_token.len() > 40);
        let found = find_valid_by_raw(&conn, &issued.raw_token).unwrap().unwrap();
        assert_eq!(found.user_id, user);
        assert_eq!(found.label, "Dan's desktop");
    }

    #[test]
    fn wrong_token_returns_none() {
        let (_d, conn, user) = scaffold();
        create(&conn, &user, "x").unwrap();
        assert!(find_valid_by_raw(&conn, "fdbx_not-a-real-token").unwrap().is_none());
        // Missing prefix also returns None fast.
        assert!(find_valid_by_raw(&conn, "some-random-string").unwrap().is_none());
    }

    #[test]
    fn revoke_blocks_verification() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "to-revoke").unwrap();
        revoke(&conn, &issued.token.id).unwrap();
        assert!(find_valid_by_raw(&conn, &issued.raw_token).unwrap().is_none());
    }

    #[test]
    fn list_returns_both_active_and_revoked() {
        let (_d, conn, user) = scaffold();
        let a = create(&conn, &user, "workstation-1").unwrap();
        let _b = create(&conn, &user, "workstation-2").unwrap();
        revoke(&conn, &a.token.id).unwrap();
        let list = list_for_user(&conn, &user).unwrap();
        assert_eq!(list.len(), 2);
        // Caller decides how to present revoked tokens.
        assert!(list.iter().any(|t| t.revoked_at.is_some()));
        assert!(list.iter().any(|t| t.revoked_at.is_none()));
    }

    #[test]
    fn last_seen_updates_on_verify() {
        let (_d, conn, user) = scaffold();
        let issued = create(&conn, &user, "x").unwrap();
        assert!(issued.token.last_seen_at.is_none());
        let _ = find_valid_by_raw(&conn, &issued.raw_token).unwrap();
        let list = list_for_user(&conn, &user).unwrap();
        assert!(list[0].last_seen_at.is_some());
    }
}

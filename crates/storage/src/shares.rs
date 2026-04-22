//! Shares — one row per file-for-a-specific-vendor instance.
//!
//! Two secrets live per share: the URL token (128 bits, inside the link) and
//! the access code (~75 bits, delivered out-of-band by SMS). The database
//! stores only SHA-256 hashes of each; the raw values are returned to the
//! caller once on [`create`] and never again.

use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, StorageError};

#[derive(Debug, Clone)]
pub struct Share {
    pub id: Uuid,
    pub print_id: Uuid,
    pub vendor_id: Uuid,
    pub token_hash: [u8; 32],
    pub access_code_hash: [u8; 32],
    pub expires_at: OffsetDateTime,
    pub max_downloads: u32,
    pub download_count: u32,
    pub sender_note: Option<String>,
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Raw secrets returned once to the caller for delivery. Never stored in the clear.
pub struct ShareSecrets {
    pub url_token: String,
    pub access_code: String,
}

/// A share joined with its vendor and print — the view model for the admin
/// list page. Carries no secrets.
#[derive(Debug, Clone)]
pub struct ShareListItem {
    pub id: Uuid,
    pub vendor_name: String,
    pub vendor_email: String,
    pub filename: String,
    pub size_bytes: u64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub max_downloads: u32,
    pub download_count: u32,
    pub revoked_at: Option<OffsetDateTime>,
    pub sender_note: Option<String>,
}

impl ShareListItem {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }

    pub fn is_exhausted(&self) -> bool {
        self.download_count >= self.max_downloads
    }

    pub fn is_active(&self) -> bool {
        !self.is_revoked() && !self.is_expired() && !self.is_exhausted()
    }

    /// Human-readable status label for the UI. Precedence: revoked > expired
    /// > exhausted > active. (A revoked-then-also-expired share displays as
    /// "revoked" because that's the more actionable fact.)
    pub fn status_label(&self) -> &'static str {
        if self.is_revoked() {
            "revoked"
        } else if self.is_expired() {
            "expired"
        } else if self.is_exhausted() {
            "downloaded"
        } else {
            "active"
        }
    }
}

pub fn create(
    conn: &Connection,
    print_id: &Uuid,
    vendor_id: &Uuid,
    expires_at: OffsetDateTime,
    max_downloads: u32,
    sender_note: Option<&str>,
    created_by: &Uuid,
) -> Result<(Share, ShareSecrets)> {
    let id = Uuid::now_v7();
    let url_token = crypto::token::url_token()?;
    let access_code = crypto::token::access_code()?;
    let token_hash = crypto::hash::sha256(url_token.as_bytes())?;
    let access_code_hash = crypto::hash::sha256(access_code.as_bytes())?;
    let now = OffsetDateTime::now_utc();

    conn.execute(
        "INSERT INTO shares
         (id, print_id, vendor_id, token_hash, access_code_hash, expires_at,
          max_downloads, download_count, sender_note, created_by, created_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, NULL)",
        params![
            id.as_bytes().as_slice(),
            print_id.as_bytes().as_slice(),
            vendor_id.as_bytes().as_slice(),
            token_hash.as_slice(),
            access_code_hash.as_slice(),
            dt_to_millis(expires_at),
            max_downloads as i64,
            sender_note,
            created_by.as_bytes().as_slice(),
            dt_to_millis(now),
        ],
    )?;

    let share = Share {
        id,
        print_id: *print_id,
        vendor_id: *vendor_id,
        token_hash,
        access_code_hash,
        expires_at,
        max_downloads,
        download_count: 0,
        sender_note: sender_note.map(|s| s.to_string()),
        created_by: *created_by,
        created_at: now,
        revoked_at: None,
    };
    let secrets = ShareSecrets {
        url_token,
        access_code,
    };
    Ok((share, secrets))
}

pub fn find_by_id(conn: &Connection, id: &Uuid) -> Result<Option<Share>> {
    conn.query_row(
        "SELECT id, print_id, vendor_id, token_hash, access_code_hash, expires_at,
                max_downloads, download_count, sender_note, created_by, created_at, revoked_at
         FROM shares WHERE id = ?1",
        params![id.as_bytes().as_slice()],
        row_to_share,
    )
    .optional()
    .map_err(Into::into)
}

/// Look up by the SHA-256 of the URL token. Callers should pass
/// `crypto::hash::sha256(token_bytes)`.
pub fn find_by_token_hash(conn: &Connection, token_hash: &[u8; 32]) -> Result<Option<Share>> {
    conn.query_row(
        "SELECT id, print_id, vendor_id, token_hash, access_code_hash, expires_at,
                max_downloads, download_count, sender_note, created_by, created_at, revoked_at
         FROM shares WHERE token_hash = ?1",
        params![token_hash.as_slice()],
        row_to_share,
    )
    .optional()
    .map_err(Into::into)
}

/// Verify a candidate access code against the share's stored hash.
/// Constant-time comparison.
pub fn verify_access_code(share: &Share, candidate: &str) -> Result<bool> {
    let h = crypto::hash::sha256(candidate.as_bytes())?;
    Ok(constant_time_eq(&h, &share.access_code_hash))
}

/// Atomically consume one download slot iff the share is still usable
/// (not revoked, not expired, not exhausted). Returns true on success.
///
/// On success, [`find_by_id`] will reflect the incremented `download_count`.
pub fn try_consume_download(conn: &Connection, share_id: &Uuid) -> Result<bool> {
    let now = dt_to_millis(OffsetDateTime::now_utc());
    let affected = conn.execute(
        "UPDATE shares
         SET download_count = download_count + 1
         WHERE id = ?1
           AND revoked_at IS NULL
           AND expires_at > ?2
           AND download_count < max_downloads",
        params![share_id.as_bytes().as_slice(), now],
    )?;
    Ok(affected == 1)
}

pub fn revoke(conn: &Connection, share_id: &Uuid) -> Result<()> {
    let now = dt_to_millis(OffsetDateTime::now_utc());
    let affected = conn.execute(
        "UPDATE shares SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
        params![now, share_id.as_bytes().as_slice()],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

/// Recent shares with vendor and filename joined, newest first.
pub fn list_recent(conn: &Connection, limit: u32) -> Result<Vec<ShareListItem>> {
    let mut stmt = conn.prepare(
        "SELECT s.id, v.display_name, v.primary_email,
                p.filename, p.size_bytes,
                s.created_at, s.expires_at, s.max_downloads, s.download_count,
                s.revoked_at, s.sender_note
         FROM shares s
         JOIN vendors v ON s.vendor_id = v.id
         JOIN prints  p ON s.print_id  = p.id
         ORDER BY s.created_at DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_list_item)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn row_to_list_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShareListItem> {
    let id_blob: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })?;
    let created_at_ms: i64 = row.get(5)?;
    let expires_at_ms: i64 = row.get(6)?;
    let max_downloads: i64 = row.get(7)?;
    let download_count: i64 = row.get(8)?;
    let revoked_at_ms: Option<i64> = row.get(9)?;
    let size_bytes: i64 = row.get(4)?;

    Ok(ShareListItem {
        id,
        vendor_name: row.get(1)?,
        vendor_email: row.get(2)?,
        filename: row.get(3)?,
        size_bytes: size_bytes as u64,
        created_at: millis_to_dt(created_at_ms),
        expires_at: millis_to_dt(expires_at_ms),
        max_downloads: max_downloads as u32,
        download_count: download_count as u32,
        revoked_at: revoked_at_ms.map(millis_to_dt),
        sender_note: row.get(10)?,
    })
}

pub fn list_by_vendor(conn: &Connection, vendor_id: &Uuid) -> Result<Vec<Share>> {
    let mut stmt = conn.prepare(
        "SELECT id, print_id, vendor_id, token_hash, access_code_hash, expires_at,
                max_downloads, download_count, sender_note, created_by, created_at, revoked_at
         FROM shares WHERE vendor_id = ?1 ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![vendor_id.as_bytes().as_slice()], row_to_share)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Remove shares that expired more than `grace_seconds` ago.
/// Blobs referenced by orphaned prints are *not* cleaned up here;
/// the service layer runs a separate sweep that joins shares with prints.
pub fn purge_expired(conn: &Connection, grace_seconds: u64) -> Result<usize> {
    let cutoff =
        dt_to_millis(OffsetDateTime::now_utc() - time::Duration::seconds(grace_seconds as i64));
    let n = conn.execute(
        "DELETE FROM shares WHERE expires_at < ?1",
        params![cutoff],
    )?;
    Ok(n)
}

fn row_to_share(row: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
    fn uuid_from(col: usize, row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<Uuid> {
        let b: Vec<u8> = row.get(col)?;
        Uuid::from_slice(&b).map_err(|_| {
            rusqlite::Error::InvalidColumnType(col, name.into(), rusqlite::types::Type::Blob)
        })
    }
    fn bytes32(col: usize, row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<[u8; 32]> {
        let v: Vec<u8> = row.get(col)?;
        if v.len() != 32 {
            return Err(rusqlite::Error::InvalidColumnType(
                col,
                name.into(),
                rusqlite::types::Type::Blob,
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }

    let id = uuid_from(0, row, "id")?;
    let print_id = uuid_from(1, row, "print_id")?;
    let vendor_id = uuid_from(2, row, "vendor_id")?;
    let token_hash = bytes32(3, row, "token_hash")?;
    let access_code_hash = bytes32(4, row, "access_code_hash")?;
    let expires_at_ms: i64 = row.get(5)?;
    let max_downloads: i64 = row.get(6)?;
    let download_count: i64 = row.get(7)?;
    let sender_note: Option<String> = row.get(8)?;
    let created_by = uuid_from(9, row, "created_by")?;
    let created_at_ms: i64 = row.get(10)?;
    let revoked_at_ms: Option<i64> = row.get(11)?;

    Ok(Share {
        id,
        print_id,
        vendor_id,
        token_hash,
        access_code_hash,
        expires_at: millis_to_dt(expires_at_ms),
        max_downloads: max_downloads as u32,
        download_count: download_count as u32,
        sender_note,
        created_by,
        created_at: millis_to_dt(created_at_ms),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prints::PrintStore, users, vendors};
    use crypto::KekManager;
    use tempfile::TempDir;
    use time::Duration;

    fn scaffold() -> (TempDir, Connection, KekManager, Uuid, Uuid, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))
            .unwrap();
        let kek = KekManager::init(dir.path().join("kek.bin")).unwrap();

        let admin =
            users::create(&conn, "a@example.com", users::UserRole::Admin, "pw1234567").unwrap();
        let vendor =
            vendors::create(&conn, "Acme", "tom@acme.com", Some("5550100"), &admin.id).unwrap();
        let blobs_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let store = PrintStore::new(&conn, &blobs_dir, &kek);
        let print = store.insert("drawing.pdf", b"contents", admin.id, true).unwrap();
        (dir, conn, kek, admin.id, vendor.id, print.id)
    }

    #[test]
    fn create_and_redeem_flow() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() + Duration::hours(72);
        let (share, secrets) =
            create(&conn, &print_id, &vendor, expires, 3, Some("rev C"), &admin).unwrap();
        assert_eq!(share.max_downloads, 3);
        assert_eq!(share.download_count, 0);

        // Look up by token_hash.
        let token_hash = crypto::hash::sha256(secrets.url_token.as_bytes()).unwrap();
        let found = find_by_token_hash(&conn, &token_hash).unwrap().unwrap();
        assert_eq!(found.id, share.id);

        // Access code verifies.
        assert!(verify_access_code(&found, &secrets.access_code).unwrap());
        assert!(!verify_access_code(&found, "WRONG-CODE-123").unwrap());

        // Consume one download.
        assert!(try_consume_download(&conn, &share.id).unwrap());
        let refreshed = find_by_id(&conn, &share.id).unwrap().unwrap();
        assert_eq!(refreshed.download_count, 1);
    }

    #[test]
    fn consume_stops_at_max() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() + Duration::hours(72);
        let (share, _) = create(&conn, &print_id, &vendor, expires, 2, None, &admin).unwrap();
        assert!(try_consume_download(&conn, &share.id).unwrap());
        assert!(try_consume_download(&conn, &share.id).unwrap());
        // Third attempt refuses.
        assert!(!try_consume_download(&conn, &share.id).unwrap());
    }

    #[test]
    fn revoked_share_cannot_consume() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() + Duration::hours(72);
        let (share, _) = create(&conn, &print_id, &vendor, expires, 5, None, &admin).unwrap();
        revoke(&conn, &share.id).unwrap();
        assert!(!try_consume_download(&conn, &share.id).unwrap());
    }

    #[test]
    fn expired_share_cannot_consume() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() - Duration::seconds(1);
        let (share, _) = create(&conn, &print_id, &vendor, expires, 5, None, &admin).unwrap();
        assert!(!try_consume_download(&conn, &share.id).unwrap());
    }

    #[test]
    fn list_recent_joins_vendor_and_print() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() + Duration::hours(72);
        let (s, _) = create(&conn, &print_id, &vendor, expires, 3, Some("rev C"), &admin).unwrap();
        let list = list_recent(&conn, 10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, s.id);
        assert_eq!(list[0].vendor_name, "Acme");
        assert_eq!(list[0].vendor_email, "tom@acme.com");
        assert_eq!(list[0].filename, "drawing.pdf");
        assert_eq!(list[0].max_downloads, 3);
        assert_eq!(list[0].download_count, 0);
        assert!(list[0].is_active());
        assert_eq!(list[0].status_label(), "active");
    }

    #[test]
    fn list_recent_status_transitions() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let future = OffsetDateTime::now_utc() + Duration::hours(72);
        let past = OffsetDateTime::now_utc() - Duration::seconds(1);

        // Active
        create(&conn, &print_id, &vendor, future, 1, None, &admin).unwrap();
        // Expired
        create(&conn, &print_id, &vendor, past, 1, None, &admin).unwrap();
        // Revoked (active but then revoked)
        let (s3, _) = create(&conn, &print_id, &vendor, future, 1, None, &admin).unwrap();
        revoke(&conn, &s3.id).unwrap();
        // Exhausted
        let (s4, _) = create(&conn, &print_id, &vendor, future, 1, None, &admin).unwrap();
        try_consume_download(&conn, &s4.id).unwrap();

        let list = list_recent(&conn, 10).unwrap();
        assert_eq!(list.len(), 4);
        let mut labels: Vec<&str> = list.iter().map(|s| s.status_label()).collect();
        labels.sort();
        assert_eq!(labels, vec!["active", "downloaded", "expired", "revoked"]);
    }

    #[test]
    fn list_by_vendor_orders_descending() {
        let (_d, conn, _kek, admin, vendor, print_id) = scaffold();
        let expires = OffsetDateTime::now_utc() + Duration::hours(72);
        let (s1, _) = create(&conn, &print_id, &vendor, expires, 1, None, &admin).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let (s2, _) = create(&conn, &print_id, &vendor, expires, 1, None, &admin).unwrap();
        let list = list_by_vendor(&conn, &vendor).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, s2.id);
        assert_eq!(list[1].id, s1.id);
    }
}

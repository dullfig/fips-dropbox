//! Prints — the actual CUI files sent to vendors.
//!
//! Storage layout:
//!   `{blobs_dir}/{first_byte_hex}/{uuid}.enc` holds the raw ciphertext.
//!   The `prints` row holds nonce, tag, SHA-256 of plaintext, and the
//!   KEK-wrapped DEK — everything needed to decrypt except the KEK itself
//!   and the host the KEK is sealed to.
//!
//! AAD for every blob is the print_id bytes. Swapping ciphertext across rows
//! therefore always fails authentication.

use crypto::{aead, hash, KekManager};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, StorageError};

#[derive(Debug, Clone)]
pub struct Print {
    pub id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256_plaintext: [u8; 32],
    /// Relative path under `blobs_dir`.
    pub blob_path: String,
    pub dek_wrapped: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub uploaded_by: Uuid,
    pub uploaded_at: OffsetDateTime,
    pub cui_attested: bool,
}

pub struct PrintStore<'a> {
    pub conn: &'a Connection,
    pub blobs_dir: &'a Path,
    pub kek: &'a KekManager,
}

impl<'a> PrintStore<'a> {
    pub fn new(conn: &'a Connection, blobs_dir: &'a Path, kek: &'a KekManager) -> Self {
        Self {
            conn,
            blobs_dir,
            kek,
        }
    }

    /// Encrypt `plaintext` and insert a prints row. On row-insert failure the
    /// already-written blob file is best-effort removed.
    pub fn insert(
        &self,
        filename: &str,
        plaintext: &[u8],
        uploaded_by: Uuid,
        cui_attested: bool,
    ) -> Result<Print> {
        let id = Uuid::now_v7();
        let sha256 = hash::sha256(plaintext)?;
        let size = plaintext.len() as u64;

        let dek = crypto::DataKey::generate()?;
        let sealed = aead::seal(&dek, id.as_bytes(), plaintext)?;
        let dek_wrapped = self.kek.wrap_dek(&dek)?;

        let prefix = format!("{:02x}", id.as_bytes()[0]);
        let full_dir = self.blobs_dir.join(&prefix);
        std::fs::create_dir_all(&full_dir)?;
        let blob_filename = format!("{}.enc", id);
        let full_path = full_dir.join(&blob_filename);
        let rel_blob_path = format!("{}/{}", prefix, blob_filename);

        std::fs::write(&full_path, &sealed.ciphertext)?;

        let now = OffsetDateTime::now_utc();
        let inserted = self.conn.execute(
            "INSERT INTO prints
             (id, filename, size_bytes, sha256_plaintext, blob_path, dek_wrapped,
              nonce, tag, uploaded_by, uploaded_at, cui_attested)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id.as_bytes().as_slice(),
                filename,
                size as i64,
                sha256.as_slice(),
                rel_blob_path,
                dek_wrapped.as_slice(),
                sealed.nonce.as_slice(),
                sealed.tag.as_slice(),
                uploaded_by.as_bytes().as_slice(),
                dt_to_millis(now),
                if cui_attested { 1i64 } else { 0i64 },
            ],
        );

        if inserted.is_err() {
            let _ = std::fs::remove_file(&full_path);
        }
        inserted?;

        Ok(Print {
            id,
            filename: filename.to_string(),
            size_bytes: size,
            sha256_plaintext: sha256,
            blob_path: rel_blob_path,
            dek_wrapped,
            nonce: sealed.nonce,
            tag: sealed.tag,
            uploaded_by,
            uploaded_at: now,
            cui_attested,
        })
    }

    pub fn find(&self, id: &Uuid) -> Result<Option<Print>> {
        self.conn
            .query_row(
                "SELECT id, filename, size_bytes, sha256_plaintext, blob_path, dek_wrapped,
                        nonce, tag, uploaded_by, uploaded_at, cui_attested
                 FROM prints WHERE id = ?1",
                params![id.as_bytes().as_slice()],
                row_to_print,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Decrypt and return the plaintext bytes. Verifies SHA-256 post-decryption.
    pub fn read_blob(&self, id: &Uuid) -> Result<Vec<u8>> {
        let print = self.find(id)?.ok_or(StorageError::NotFound)?;
        let full_path = self.blobs_dir.join(&print.blob_path);
        let ct = std::fs::read(&full_path)?;
        let dek = self.kek.unwrap_dek(&print.dek_wrapped)?;
        let sealed = aead::Sealed {
            nonce: print.nonce,
            ciphertext: ct,
            tag: print.tag,
        };
        let pt = aead::open(&dek, print.id.as_bytes(), &sealed)?;
        let got = hash::sha256(&pt)?;
        if got != print.sha256_plaintext {
            return Err(StorageError::Crypto(crypto::CryptoError::DecryptionFailed));
        }
        Ok(pt)
    }

    pub fn delete(&self, id: &Uuid) -> Result<()> {
        let print = self.find(id)?.ok_or(StorageError::NotFound)?;
        self.conn.execute(
            "DELETE FROM prints WHERE id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        let full_path = self.blobs_dir.join(&print.blob_path);
        let _ = std::fs::remove_file(&full_path);
        Ok(())
    }
}

fn row_to_print(row: &rusqlite::Row<'_>) -> rusqlite::Result<Print> {
    let id_blob: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })?;
    let size_bytes: i64 = row.get(2)?;

    let sha256_vec: Vec<u8> = row.get(3)?;
    let mut sha256 = [0u8; 32];
    if sha256_vec.len() != 32 {
        return Err(rusqlite::Error::InvalidColumnType(
            3,
            "sha256_plaintext".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    sha256.copy_from_slice(&sha256_vec);

    let nonce_vec: Vec<u8> = row.get(6)?;
    let mut nonce = [0u8; 12];
    if nonce_vec.len() != 12 {
        return Err(rusqlite::Error::InvalidColumnType(
            6,
            "nonce".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    nonce.copy_from_slice(&nonce_vec);

    let tag_vec: Vec<u8> = row.get(7)?;
    let mut tag = [0u8; 16];
    if tag_vec.len() != 16 {
        return Err(rusqlite::Error::InvalidColumnType(
            7,
            "tag".into(),
            rusqlite::types::Type::Blob,
        ));
    }
    tag.copy_from_slice(&tag_vec);

    let uploader_vec: Vec<u8> = row.get(8)?;
    let uploaded_by = Uuid::from_slice(&uploader_vec).map_err(|_| {
        rusqlite::Error::InvalidColumnType(8, "uploaded_by".into(), rusqlite::types::Type::Blob)
    })?;
    let uploaded_at_ms: i64 = row.get(9)?;
    let cui_attested_int: i64 = row.get(10)?;

    Ok(Print {
        id,
        filename: row.get(1)?,
        size_bytes: size_bytes as u64,
        sha256_plaintext: sha256,
        blob_path: row.get(4)?,
        dek_wrapped: row.get(5)?,
        nonce,
        tag,
        uploaded_by,
        uploaded_at: millis_to_dt(uploaded_at_ms),
        cui_attested: cui_attested_int != 0,
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

    fn fresh_everything() -> (TempDir, Connection, KekManager, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))
            .unwrap();
        let kek = KekManager::init(dir.path().join("kek.bin")).unwrap();
        let admin =
            users::create(&conn, "a@example.com", users::UserRole::Admin, "pw1234567").unwrap();
        (dir, conn, kek, admin.id)
    }

    #[test]
    fn insert_find_read_round_trip() {
        let (dir, conn, kek, admin) = fresh_everything();
        let blobs_dir = dir.path().join("blobs");
        let store = PrintStore::new(&conn, &blobs_dir, &kek);
        let data = b"drawing contents for part 17842 revision C";
        let p = store.insert("part17842.pdf", data, admin, true).unwrap();
        let found = store.find(&p.id).unwrap().unwrap();
        assert_eq!(found.filename, "part17842.pdf");
        assert_eq!(found.size_bytes, data.len() as u64);
        let decrypted = store.read_blob(&p.id).unwrap();
        assert_eq!(decrypted.as_slice(), data.as_slice());
    }

    #[test]
    fn tampered_blob_fails_to_decrypt() {
        let (dir, conn, kek, admin) = fresh_everything();
        let blobs_dir = dir.path().join("blobs");
        let store = PrintStore::new(&conn, &blobs_dir, &kek);
        let p = store.insert("x.txt", b"secret", admin, true).unwrap();
        let full = blobs_dir.join(&p.blob_path);
        let mut bytes = std::fs::read(&full).unwrap();
        bytes[0] ^= 0x01;
        std::fs::write(&full, &bytes).unwrap();
        let r = store.read_blob(&p.id);
        assert!(r.is_err(), "tampered blob must not decrypt");
    }

    #[test]
    fn swapped_blob_fails_aad_check() {
        // Overwrite blob A's ciphertext with blob B's. Since AAD = print_id
        // is baked into the tag, decryption with A's row (A's nonce/tag/DEK)
        // over B's ciphertext should fail.
        let (dir, conn, kek, admin) = fresh_everything();
        let blobs_dir = dir.path().join("blobs");
        let store = PrintStore::new(&conn, &blobs_dir, &kek);
        let a = store.insert("a.txt", b"aaaaaa", admin, true).unwrap();
        let b = store.insert("b.txt", b"bbbbbb", admin, true).unwrap();
        let a_path = blobs_dir.join(&a.blob_path);
        let b_path = blobs_dir.join(&b.blob_path);
        let b_ct = std::fs::read(&b_path).unwrap();
        std::fs::write(&a_path, &b_ct).unwrap();
        let r = store.read_blob(&a.id);
        assert!(r.is_err(), "swapped blob must fail auth");
    }

    #[test]
    fn delete_removes_row_and_file() {
        let (dir, conn, kek, admin) = fresh_everything();
        let blobs_dir = dir.path().join("blobs");
        let store = PrintStore::new(&conn, &blobs_dir, &kek);
        let p = store.insert("x.txt", b"bye", admin, true).unwrap();
        let full = blobs_dir.join(&p.blob_path);
        assert!(full.exists());
        store.delete(&p.id).unwrap();
        assert!(!full.exists());
        assert!(store.find(&p.id).unwrap().is_none());
    }
}

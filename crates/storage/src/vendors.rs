//! Vendors — the outside parties we send files to.

use rusqlite::{params, Connection, OptionalExtension};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, StorageError};

#[derive(Debug, Clone)]
pub struct Vendor {
    pub id: Uuid,
    pub display_name: String,
    pub primary_email: String,
    pub primary_phone: Option<String>,
    pub primary_user_id: Option<Uuid>,
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub disabled_at: Option<OffsetDateTime>,
}

pub fn create(
    conn: &Connection,
    display_name: &str,
    email: &str,
    phone: Option<&str>,
    created_by: &Uuid,
) -> Result<Vendor> {
    let id = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();
    conn.execute(
        "INSERT INTO vendors
         (id, display_name, primary_email, primary_phone, primary_user_id,
          created_by, created_at, disabled_at)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, NULL)",
        params![
            id.as_bytes().as_slice(),
            display_name,
            email,
            phone,
            created_by.as_bytes().as_slice(),
            dt_to_millis(now),
        ],
    )?;
    Ok(Vendor {
        id,
        display_name: display_name.to_string(),
        primary_email: email.to_string(),
        primary_phone: phone.map(|s| s.to_string()),
        primary_user_id: None,
        created_by: *created_by,
        created_at: now,
        disabled_at: None,
    })
}

pub fn find_by_id(conn: &Connection, id: &Uuid) -> Result<Option<Vendor>> {
    conn.query_row(
        "SELECT id, display_name, primary_email, primary_phone, primary_user_id,
                created_by, created_at, disabled_at
         FROM vendors WHERE id = ?1",
        params![id.as_bytes().as_slice()],
        row_to_vendor,
    )
    .optional()
    .map_err(Into::into)
}

pub fn find_by_email(conn: &Connection, email: &str) -> Result<Option<Vendor>> {
    conn.query_row(
        "SELECT id, display_name, primary_email, primary_phone, primary_user_id,
                created_by, created_at, disabled_at
         FROM vendors WHERE primary_email = ?1 AND disabled_at IS NULL",
        params![email],
        row_to_vendor,
    )
    .optional()
    .map_err(Into::into)
}

pub fn list_active(conn: &Connection) -> Result<Vec<Vendor>> {
    let mut stmt = conn.prepare(
        "SELECT id, display_name, primary_email, primary_phone, primary_user_id,
                created_by, created_at, disabled_at
         FROM vendors WHERE disabled_at IS NULL ORDER BY display_name",
    )?;
    let rows = stmt.query_map([], row_to_vendor)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn disable(conn: &Connection, id: &Uuid) -> Result<()> {
    let now = dt_to_millis(OffsetDateTime::now_utc());
    let affected = conn.execute(
        "UPDATE vendors SET disabled_at = ?1 WHERE id = ?2 AND disabled_at IS NULL",
        params![now, id.as_bytes().as_slice()],
    )?;
    if affected == 0 {
        Err(StorageError::NotFound)
    } else {
        Ok(())
    }
}

fn row_to_vendor(row: &rusqlite::Row<'_>) -> rusqlite::Result<Vendor> {
    let id_blob: Vec<u8> = row.get(0)?;
    let id = Uuid::from_slice(&id_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Blob)
    })?;
    let primary_user_id_blob: Option<Vec<u8>> = row.get(4)?;
    let primary_user_id = match primary_user_id_blob {
        Some(b) => Some(Uuid::from_slice(&b).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                4,
                "primary_user_id".into(),
                rusqlite::types::Type::Blob,
            )
        })?),
        None => None,
    };
    let created_by_blob: Vec<u8> = row.get(5)?;
    let created_by = Uuid::from_slice(&created_by_blob).map_err(|_| {
        rusqlite::Error::InvalidColumnType(5, "created_by".into(), rusqlite::types::Type::Blob)
    })?;
    let created_at_ms: i64 = row.get(6)?;
    let disabled_at_ms: Option<i64> = row.get(7)?;
    Ok(Vendor {
        id,
        display_name: row.get(1)?,
        primary_email: row.get(2)?,
        primary_phone: row.get(3)?,
        primary_user_id,
        created_by,
        created_at: millis_to_dt(created_at_ms),
        disabled_at: disabled_at_ms.map(millis_to_dt),
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

    fn fresh_db() -> (TempDir, Connection, Uuid) {
        let dir = TempDir::new().unwrap();
        let conn = Connection::open(dir.path().join("test.db")).unwrap();
        conn.execute_batch(include_str!("../../../migrations/0001_initial.sql"))
            .unwrap();
        let admin =
            users::create(&conn, "admin@example.com", users::UserRole::Admin, "pw1234567")
                .unwrap();
        (dir, conn, admin.id)
    }

    #[test]
    fn create_find_list() {
        let (_d, conn, admin) = fresh_db();
        let v = create(
            &conn,
            "Acme Tool & Die",
            "tom@acmetoolndie.com",
            Some("5551239999"),
            &admin,
        )
        .unwrap();
        assert_eq!(v.display_name, "Acme Tool & Die");

        let f = find_by_id(&conn, &v.id).unwrap().unwrap();
        assert_eq!(f.primary_email, "tom@acmetoolndie.com");

        let fe = find_by_email(&conn, "tom@acmetoolndie.com").unwrap().unwrap();
        assert_eq!(fe.id, v.id);

        let all = list_active(&conn).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn disable_hides_from_list_and_lookup() {
        let (_d, conn, admin) = fresh_db();
        let v = create(&conn, "Bravo", "b@example.com", None, &admin).unwrap();
        disable(&conn, &v.id).unwrap();
        assert!(list_active(&conn).unwrap().is_empty());
        assert!(find_by_email(&conn, "b@example.com").unwrap().is_none());
        // find_by_id still works — needed for audit log back-references.
        assert!(find_by_id(&conn, &v.id).unwrap().is_some());
    }
}

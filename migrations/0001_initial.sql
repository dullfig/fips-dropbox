-- fips-dropbox initial schema
-- SQLite. All UUIDs stored as 16-byte BLOBs. All timestamps stored as INTEGER
-- (unix epoch milliseconds) for portability across sqlite versions.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS users (
    id               BLOB PRIMARY KEY,
    email            TEXT NOT NULL UNIQUE,
    role             TEXT NOT NULL CHECK (role IN ('admin', 'vendor')),
    password_hash    BLOB NOT NULL,
    password_salt    BLOB NOT NULL,
    password_iters   INTEGER NOT NULL,
    totp_secret_wrapped BLOB,
    created_at       INTEGER NOT NULL,
    disabled_at      INTEGER
);

CREATE TABLE IF NOT EXISTS vendors (
    id               BLOB PRIMARY KEY,
    display_name     TEXT NOT NULL,
    primary_email    TEXT NOT NULL,
    primary_phone    TEXT,
    primary_user_id  BLOB REFERENCES users(id),
    created_by       BLOB NOT NULL REFERENCES users(id),
    created_at       INTEGER NOT NULL,
    disabled_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_vendors_email ON vendors(primary_email);

CREATE TABLE IF NOT EXISTS prints (
    id               BLOB PRIMARY KEY,
    filename         TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    sha256_plaintext BLOB NOT NULL,
    blob_path        TEXT NOT NULL,
    dek_wrapped      BLOB NOT NULL,
    nonce            BLOB NOT NULL,
    tag              BLOB NOT NULL,
    uploaded_by      BLOB NOT NULL REFERENCES users(id),
    uploaded_at      INTEGER NOT NULL,
    cui_attested     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS shares (
    id               BLOB PRIMARY KEY,
    print_id         BLOB NOT NULL REFERENCES prints(id),
    vendor_id        BLOB NOT NULL REFERENCES vendors(id),
    token_hash       BLOB NOT NULL UNIQUE,
    access_code_hash BLOB NOT NULL,
    expires_at       INTEGER NOT NULL,
    max_downloads    INTEGER NOT NULL,
    download_count   INTEGER NOT NULL DEFAULT 0,
    sender_note      TEXT,
    created_by       BLOB NOT NULL REFERENCES users(id),
    created_at       INTEGER NOT NULL,
    revoked_at       INTEGER
);

CREATE INDEX IF NOT EXISTS idx_shares_vendor ON shares(vendor_id);
CREATE INDEX IF NOT EXISTS idx_shares_token ON shares(token_hash);

CREATE TABLE IF NOT EXISTS sessions (
    id               BLOB PRIMARY KEY,
    user_id          BLOB NOT NULL REFERENCES users(id),
    csrf_token       BLOB NOT NULL,
    ip               TEXT NOT NULL,
    user_agent       TEXT NOT NULL,
    expires_at       INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Per-workstation API tokens used by the tray agent (and future CLI/API
-- consumers). The raw token is shown once at creation; only sha256(raw) is
-- stored so a DB leak does not compromise any credential.
CREATE TABLE IF NOT EXISTS api_tokens (
    id              BLOB PRIMARY KEY,
    user_id         BLOB NOT NULL REFERENCES users(id),
    label           TEXT NOT NULL,
    token_hash      BLOB NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    revoked_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);

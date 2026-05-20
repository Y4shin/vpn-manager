CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    oidc_sub        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    groups_json     TEXT NOT NULL DEFAULT '[]',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    public_key           TEXT NOT NULL UNIQUE,
    ip                   TEXT NOT NULL UNIQUE,
    group_at_creation    TEXT NOT NULL,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_handshake_at    DATETIME
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS sessions (
    token   TEXT PRIMARY KEY,
    data    BLOB NOT NULL,
    expiry  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expiry);

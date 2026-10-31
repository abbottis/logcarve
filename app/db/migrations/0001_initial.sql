-- 0001: initial T3 domain tables (spec section 2.5).
-- Normalized request events only: no raw lines, original IPs or secrets.
-- bot_family/bot_confidence stay NULL until the T4 analytics slice fills them.
-- findings are derived on read (ADR 0002 decision 6) and have no table.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_sources (
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites (id),
    server_type TEXT NOT NULL,
    format_id TEXT NOT NULL,
    path_alias TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL REFERENCES log_sources (id),
    file_fingerprint TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    lines_total INTEGER NOT NULL DEFAULT 0,
    lines_accepted INTEGER NOT NULL DEFAULT 0,
    lines_rejected INTEGER NOT NULL DEFAULT 0,
    records_inserted INTEGER NOT NULL DEFAULT 0,
    records_replayed INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error_summary TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id INTEGER NOT NULL REFERENCES imports (id),
    site_id TEXT NOT NULL REFERENCES sites (id),
    source_id TEXT NOT NULL REFERENCES log_sources (id),
    file_fingerprint TEXT NOT NULL,
    byte_offset INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    ts_utc TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    bytes INTEGER,
    referer_host TEXT,
    user_agent TEXT,
    client_pseudonym TEXT NOT NULL,
    bot_family TEXT,
    bot_confidence REAL,
    duration_ms REAL,
    UNIQUE (source_id, file_fingerprint, byte_offset)
);

CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests (ts_utc);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests (status);
CREATE INDEX IF NOT EXISTS idx_requests_path ON requests (path);
CREATE INDEX IF NOT EXISTS idx_requests_source ON requests (source_id);

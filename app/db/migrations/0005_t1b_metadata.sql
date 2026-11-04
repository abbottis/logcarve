-- 0005: T1b nullable enrichment metadata + encrypted original-IP store.
-- New metadata columns stay NULL on legacy rows until an explicit
-- read-only source reprocess enriches them. Core event identity
-- (ids, fingerprint/offset, HMAC pseudonyms), legacy duration_ms,
-- auth tables, model usage and allowance rows are untouched.
-- Original addresses live ONLY in request_original_ips as AESGCM
-- ciphertext bound to site/source/event identity, cascading with
-- their parent request rows. Backups hold ciphertext only.

ALTER TABLE requests ADD COLUMN format_id TEXT;
ALTER TABLE requests ADD COLUMN http_version TEXT;
ALTER TABLE requests ADD COLUMN server_host TEXT;
ALTER TABLE requests ADD COLUMN referer_scheme TEXT;
ALTER TABLE requests ADD COLUMN referer_path TEXT;
ALTER TABLE requests ADD COLUMN cache_status TEXT;
ALTER TABLE requests ADD COLUMN mime_type TEXT;
ALTER TABLE requests ADD COLUMN tls_protocol TEXT;
ALTER TABLE requests ADD COLUMN request_time_ms REAL;
ALTER TABLE requests ADD COLUMN upstream_time_ms REAL;
-- Nullable: pre-existing rows keep NULL until an explicit reprocess
-- enriches them; absent upstream timing parses to NULL, never 0.
ALTER TABLE requests ADD COLUMN upstream_count INTEGER;
-- Explicit parser/normalization policy tag (see PARSER_POLICY_VERSION);
-- NULL on legacy rows, set on new imports and reprocess enrichment.
ALTER TABLE requests ADD COLUMN policy_version TEXT;

ALTER TABLE log_sources ADD COLUMN allowed_hosts TEXT;

CREATE TABLE IF NOT EXISTS request_original_ips (
    request_id INTEGER PRIMARY KEY REFERENCES requests (id) ON DELETE CASCADE,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

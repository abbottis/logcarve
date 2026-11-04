-- 0009: explicit bounded runtime usage authorization (ADR 0004).
-- Separate from the historical once-only T8 smoke ledger (0004):
-- real provider dispatches additionally require a runtime grant
-- created by an explicit operator action. No row means fail-closed
-- (usage_not_authorized); settings save/enable/restart never create
-- or modify these rows. Amounts and counts only: no prompts or content.

CREATE TABLE IF NOT EXISTS runtime_allowance (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    max_investigations INTEGER NOT NULL CHECK (max_investigations >= 0),
    max_requests INTEGER NOT NULL CHECK (max_requests >= 0),
    max_micro_usd INTEGER NOT NULL CHECK (max_micro_usd >= 0),
    used_investigations INTEGER NOT NULL DEFAULT 0 CHECK (used_investigations >= 0),
    used_requests INTEGER NOT NULL DEFAULT 0 CHECK (used_requests >= 0),
    used_micro_usd INTEGER NOT NULL DEFAULT 0 CHECK (used_micro_usd >= 0),
    held_micro_usd INTEGER NOT NULL DEFAULT 0 CHECK (held_micro_usd >= 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_holds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    amount_micro_usd INTEGER NOT NULL CHECK (amount_micro_usd >= 0),
    status TEXT NOT NULL DEFAULT 'active',
    investigation_id TEXT,
    created_at TEXT NOT NULL,
    settled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_runtime_holds_status ON runtime_holds (status);

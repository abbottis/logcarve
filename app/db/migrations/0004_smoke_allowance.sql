-- 0004: lifetime smoke allowance for the single capped T8 approval.
-- Counters never reset at UTC midnight and never renew: one versioned
-- row holds the caps snapshot plus lifetime used/held amounts, and
-- every hold is a row so concurrent runners and restarts share the
-- same counters. Amounts and counts only: no prompts or content.

CREATE TABLE IF NOT EXISTS smoke_allowance (
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

CREATE TABLE IF NOT EXISTS smoke_holds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    amount_micro_usd INTEGER NOT NULL CHECK (amount_micro_usd >= 0),
    status TEXT NOT NULL DEFAULT 'active',
    investigation_id TEXT,
    created_at TEXT NOT NULL,
    settled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_smoke_holds_status ON smoke_holds (status);

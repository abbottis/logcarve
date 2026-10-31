-- 0003: durable AI budget ledger (T7).
-- Every reservation and charge is a row, so a restart or a second
-- worker can neither reset nor double-spend the budget. Reservations
-- hold funds until released or converted to a measured charge.
-- No prompts, logs, IPs or secrets are stored here: amounts only.

CREATE TABLE IF NOT EXISTS ai_spend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    day TEXT NOT NULL,
    kind TEXT NOT NULL,
    amount_micro_usd INTEGER NOT NULL CHECK (amount_micro_usd >= 0),
    status TEXT NOT NULL DEFAULT 'active',
    investigation_id TEXT,
    created_at TEXT NOT NULL,
    settled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_ai_spend_day ON ai_spend (day, status);

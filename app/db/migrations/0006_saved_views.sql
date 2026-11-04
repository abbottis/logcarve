-- 0006: session-owned saved filter views (T4c bookmarks).
-- Each row belongs to exactly one local admin user; rows never carry
-- secrets, keys, raw addresses or source paths -- only the allowlisted
-- dashboard path plus its validated query string, re-validated on
-- every open. Existing imported data is untouched.

CREATE TABLE IF NOT EXISTS saved_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES admin_users (id),
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saved_views_user ON saved_views (user_id);

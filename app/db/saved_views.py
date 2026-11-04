"""Session-owned saved filter views (T4c bookmarks).

Each row belongs to exactly one local admin user (``user_id`` from the
admin session): all reads and writes filter by that owner, so one
user can never list, rename, update or delete another user's view.
Rows carry only the allowlisted dashboard path plus its validated
query string — never secrets, keys, raw addresses or source paths —
re-validated on every save and on every open by the normal page
handlers. Names and counts are bounded; unknown paths, parameters
and redirect targets reject instead of widening.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime


def _now() -> str:
    return datetime.now(UTC).isoformat()


def list_for_user(conn: sqlite3.Connection, user_id: int) -> list[dict[str, object]]:
    """Saved views owned by ``user_id``, newest update first."""
    rows = conn.execute(
        "SELECT id, user_id, name, path, query, created_at, updated_at"
        " FROM saved_views WHERE user_id = ? ORDER BY updated_at DESC, id DESC",
        (user_id,),
    ).fetchall()
    return [
        {
            "id": row[0],
            "user_id": row[1],
            "name": row[2],
            "path": row[3],
            "query": row[4],
            "created_at": row[5],
            "updated_at": row[6],
            "url": row[3] + ("?" + row[4] if row[4] else ""),
        }
        for row in rows
    ]


def count_for_user(conn: sqlite3.Connection, user_id: int) -> int:
    """Number of saved views owned by ``user_id`` (for the count bound)."""
    row = conn.execute("SELECT COUNT(*) FROM saved_views WHERE user_id = ?", (user_id,)).fetchone()
    return int(row[0]) if row is not None else 0


def get_for_user(conn: sqlite3.Connection, view_id: int, user_id: int) -> dict[str, object] | None:
    """One saved view by id, only when owned by ``user_id``."""
    row = conn.execute(
        "SELECT id, user_id, name, path, query, created_at, updated_at"
        " FROM saved_views WHERE id = ? AND user_id = ?",
        (view_id, user_id),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "user_id": row[1],
        "name": row[2],
        "path": row[3],
        "query": row[4],
        "created_at": row[5],
        "updated_at": row[6],
        "url": row[3] + ("?" + row[4] if row[4] else ""),
    }


def create(
    conn: sqlite3.Connection,
    user_id: int,
    name: str,
    path: str,
    query: str,
) -> int:
    """Insert one validated view; returns the new id."""
    moment = _now()
    cursor = conn.execute(
        "INSERT INTO saved_views (user_id, name, path, query, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, path, query, moment, moment),
    )
    return int(cursor.lastrowid)


def rename(conn: sqlite3.Connection, view_id: int, user_id: int, name: str) -> bool:
    """Rename one owned view; False when the id is unknown or foreign."""
    cursor = conn.execute(
        "UPDATE saved_views SET name = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (name, _now(), view_id, user_id),
    )
    return cursor.rowcount == 1


def retarget(
    conn: sqlite3.Connection,
    view_id: int,
    user_id: int,
    path: str,
    query: str,
) -> bool:
    """Replace one owned view's validated target; False when foreign."""
    cursor = conn.execute(
        "UPDATE saved_views SET path = ?, query = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (path, query, _now(), view_id, user_id),
    )
    return cursor.rowcount == 1


def delete(conn: sqlite3.Connection, view_id: int, user_id: int) -> bool:
    """Delete one owned view; False when the id is unknown or foreign."""
    cursor = conn.execute(
        "DELETE FROM saved_views WHERE id = ? AND user_id = ?", (view_id, user_id)
    )
    return cursor.rowcount == 1

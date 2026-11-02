"""Explicit bounded runtime usage authorization for real AI calls (ADR 0004).

Separate from the historical once-only T8 smoke ledger (which is
preserved untouched): real provider dispatches additionally require a
runtime grant created by an explicit operator action
(``logcarve ai-allowance-grant``). There is initially NO grant, so
defaults fail closed with ``usage_not_authorized`` while deterministic
analytics keep working. Enabling AI in the UI alone never creates a
grant, and provider/key/enable/save/restart events never
reset/clear/expand/bypass it.

Grants are global across providers (switching providers never renews
them) and capped in investigations, requests and micro-USD, counting
failures and retries: admission happens before dispatch and work of
unknown size keeps its full hold. A narrower re-grant tightens caps
immediately; recorded spend is never refunded or reset.

Recorded data carries amounts and counts only, never prompts,
responses or evidence content.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.db.database import writer_transaction

ALLOWANCE_VERSION = 1


class AllowanceRefused(RuntimeError):
    """The runtime allowance cannot admit this work under its caps."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _row(conn: sqlite3.Connection):
    return conn.execute(
        "SELECT version, max_investigations, max_requests, max_micro_usd,"
        " used_investigations, used_requests, used_micro_usd, held_micro_usd"
        " FROM runtime_allowance WHERE id = 1"
    ).fetchone()


def status(db_path: Path) -> dict | None:
    """Current grant snapshot, or None when no grant was ever created."""
    from app.db.database import connect

    try:
        conn = connect(Path(db_path), read_only=True)
    except Exception:  # noqa: BLE001 - unreadable store means no grant
        return None
    try:
        current = _row(conn)
    except Exception:  # noqa: BLE001 - unreadable row means no grant
        return None
    finally:
        conn.close()
    if current is None:
        return None
    return {
        "max_investigations": current[1],
        "max_requests": current[2],
        "max_micro_usd": current[3],
        "used_investigations": current[4],
        "used_requests": current[5],
        "used_micro_usd": current[6],
        "held_micro_usd": current[7],
    }


def grant(db_path: Path, *, max_investigations: int, max_requests: int, max_micro_usd: int) -> dict:
    """Create or narrow the runtime grant (explicit operator action only)."""
    for value in (max_investigations, max_requests, max_micro_usd):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("grant caps must be non-negative integers")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            conn.execute(
                "INSERT INTO runtime_allowance (id, version, max_investigations,"
                " max_requests, max_micro_usd, used_investigations, used_requests,"
                " used_micro_usd, held_micro_usd, updated_at)"
                " VALUES (1, ?, ?, ?, ?, 0, 0, 0, 0, ?)",
                (ALLOWANCE_VERSION, max_investigations, max_requests, max_micro_usd, now),
            )
            current = _row(conn)
            assert current is not None
            return {
                "max_investigations": current[1],
                "max_requests": current[2],
                "max_micro_usd": current[3],
            }
        version, cap_inv, cap_req, cap_usd = current[0], current[1], current[2], current[3]
        if version != ALLOWANCE_VERSION:
            raise AllowanceRefused(
                "allowance_version_mismatch", "The runtime allowance schema is not supported."
            )
        if max_investigations > cap_inv or max_requests > cap_req or max_micro_usd > cap_usd:
            raise AllowanceRefused(
                "allowance_widened",
                "The runtime allowance cannot be widened implicitly.",
            )
        narrowed = (
            min(cap_inv, max_investigations),
            min(cap_req, max_requests),
            min(cap_usd, max_micro_usd),
        )
        if narrowed != (cap_inv, cap_req, cap_usd):
            conn.execute(
                "UPDATE runtime_allowance SET max_investigations = ?,"
                " max_requests = ?, max_micro_usd = ?, updated_at = ? WHERE id = 1",
                (*narrowed, now),
            )
        return {
            "max_investigations": narrowed[0],
            "max_requests": narrowed[1],
            "max_micro_usd": narrowed[2],
        }


def admit_investigation(db_path: Path, *, investigation_id: str) -> None:
    """Count one investigation against the grant before it starts."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            raise AllowanceRefused(
                "usage_not_authorized", "No runtime AI usage allowance has been granted."
            )
        if current[4] + 1 > current[1]:
            raise AllowanceRefused(
                "investigation_cap_reached", "The runtime AI investigation allowance is exhausted."
            )
        conn.execute(
            "UPDATE runtime_allowance SET used_investigations = used_investigations + 1,"
            " updated_at = ? WHERE id = 1",
            (now,),
        )


def admit_request(db_path: Path, *, amount_micro_usd: int, investigation_id: str) -> int:
    """Atomically admit one provider request (failed attempts included)."""
    if amount_micro_usd < 0:
        raise ValueError("hold amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            raise AllowanceRefused(
                "usage_not_authorized", "No runtime AI usage allowance has been granted."
            )
        if current[5] + 1 > current[2]:
            raise AllowanceRefused(
                "request_cap_reached", "The runtime AI request allowance is exhausted."
            )
        if current[7] + current[6] + amount_micro_usd > current[3]:
            raise AllowanceRefused(
                "cost_cap_reached", "The runtime AI cost allowance is exhausted."
            )
        cursor = conn.execute(
            "INSERT INTO runtime_holds (amount_micro_usd, status, investigation_id,"
            " created_at) VALUES (?, 'active', ?, ?)",
            (amount_micro_usd, investigation_id, now),
        )
        hold_id = cursor.lastrowid
        assert hold_id is not None
        conn.execute(
            "UPDATE runtime_allowance SET used_requests = used_requests + 1,"
            " held_micro_usd = held_micro_usd + ?, updated_at = ? WHERE id = 1",
            (amount_micro_usd, now),
        )
        return hold_id


def settle_hold(db_path: Path, *, hold_id: int, actual_micro_usd: int) -> None:
    """Convert a hold into a measured charge for the actual spend."""
    if actual_micro_usd < 0:
        raise ValueError("charge amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM runtime_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE runtime_holds SET status = 'charged', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE runtime_allowance SET held_micro_usd = held_micro_usd - ?,"
            " used_micro_usd = used_micro_usd + ?, updated_at = ? WHERE id = 1",
            (row[0], actual_micro_usd, now),
        )


def release_hold(db_path: Path, *, hold_id: int) -> None:
    """Release a hold for work that never dispatched."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM runtime_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE runtime_holds SET status = 'released', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE runtime_allowance SET held_micro_usd = held_micro_usd - ?,"
            " updated_at = ? WHERE id = 1",
            (row[0], now),
        )


def abandon_hold(db_path: Path, *, hold_id: int) -> None:
    """Keep the full hold for dispatched work of unknown size."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM runtime_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE runtime_holds SET status = 'charged', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE runtime_allowance SET held_micro_usd = held_micro_usd - ?,"
            " used_micro_usd = used_micro_usd + ?, updated_at = ? WHERE id = 1",
            (row[0], row[0], now),
        )

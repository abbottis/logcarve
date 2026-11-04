"""Lifetime smoke allowance for the single capped T8 approval (T8).

Counters are LIFETIME for this approval: they never reset at UTC
midnight and never renew automatically (normal daily ``ai_spend``
accounting still rolls UTC separately). One versioned row holds the
caps snapshot plus used/held amounts; every admission, hold and
settlement runs inside a writer transaction, so concurrent runners
and restarts share the same counters. Failed attempts and in-flight
work count: admission happens before dispatch, and work of unknown
size keeps its full hold.

Recorded data carries amounts and counts only, never prompts,
responses or evidence content.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.db.database import writer_transaction

ALLOWANCE_VERSION = 1


class SmokeRefused(RuntimeError):
    """The smoke allowance cannot admit this work under its lifetime caps."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _row(conn: sqlite3.Connection):
    return conn.execute(
        "SELECT version, max_investigations, max_requests, max_micro_usd,"
        " used_investigations, used_requests, used_micro_usd, held_micro_usd"
        " FROM smoke_allowance WHERE id = 1"
    ).fetchone()


def init_or_check(
    db_path: Path, *, max_investigations: int, max_requests: int, max_micro_usd: int
) -> dict:
    """Create the lifetime row on first use; refuse silent widening after."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            conn.execute(
                "INSERT INTO smoke_allowance (id, version, max_investigations,"
                " max_requests, max_micro_usd, used_investigations, used_requests,"
                " used_micro_usd, held_micro_usd, updated_at)"
                " VALUES (1, ?, ?, ?, ?, 0, 0, 0, 0, ?)",
                (ALLOWANCE_VERSION, max_investigations, max_requests, max_micro_usd, now),
            )
            current = _row(conn)
        assert current is not None
        version, cap_inv, cap_req, cap_usd = current[0], current[1], current[2], current[3]
        if version != ALLOWANCE_VERSION:
            raise SmokeRefused(
                "allowance_version_mismatch", "The smoke allowance schema is not supported."
            )
        if max_investigations > cap_inv or max_requests > cap_req or max_micro_usd > cap_usd:
            raise SmokeRefused(
                "allowance_widened",
                "The smoke allowance cannot be widened after first use.",
            )
        # Tightening applies atomically: persist the minimum caps so
        # narrower approvals bind immediately. Recorded spend is never
        # refunded or reset.
        narrowed = (
            min(cap_inv, max_investigations),
            min(cap_req, max_requests),
            min(cap_usd, max_micro_usd),
        )
        if narrowed != (cap_inv, cap_req, cap_usd):
            conn.execute(
                "UPDATE smoke_allowance SET max_investigations = ?,"
                " max_requests = ?, max_micro_usd = ?, updated_at = ? WHERE id = 1",
                (*narrowed, now),
            )
            cap_inv, cap_req, cap_usd = narrowed
        return {
            "max_investigations": cap_inv,
            "max_requests": cap_req,
            "max_micro_usd": cap_usd,
            "used_investigations": current[4],
            "used_requests": current[5],
            "used_micro_usd": current[6],
            "held_micro_usd": current[7],
        }


def admit_investigation(db_path: Path, *, investigation_id: str) -> None:
    """Count one investigation against the lifetime cap before it starts."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            raise SmokeRefused("allowance_missing", "The smoke allowance is not initialized.")
        if current[4] + 1 > current[1]:
            raise SmokeRefused(
                "investigation_cap_reached", "The smoke investigation allowance is exhausted."
            )
        conn.execute(
            "UPDATE smoke_allowance SET used_investigations = used_investigations + 1,"
            " updated_at = ? WHERE id = 1",
            (now,),
        )


def admit_request(db_path: Path, *, amount_micro_usd: int, investigation_id: str) -> int:
    """Atomically admit one provider request (failed attempts included).

    Returns a hold id; the hold keeps its full amount until settled.
    """
    if amount_micro_usd < 0:
        raise ValueError("hold amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        current = _row(conn)
        if current is None:
            raise SmokeRefused("allowance_missing", "The smoke allowance is not initialized.")
        _, _, cap_req, cap_usd, _, used_req, used_usd, held_usd = current
        if used_req + 1 > cap_req:
            raise SmokeRefused("request_cap_reached", "The smoke request allowance is exhausted.")
        if used_usd + held_usd + amount_micro_usd > cap_usd:
            raise SmokeRefused("cost_cap_reached", "The smoke cost allowance is exhausted.")
        cursor = conn.execute(
            "INSERT INTO smoke_holds (amount_micro_usd, status, investigation_id, created_at)"
            " VALUES (?, 'active', ?, ?)",
            (amount_micro_usd, investigation_id, now),
        )
        hold_id = cursor.lastrowid
        assert hold_id is not None
        conn.execute(
            "UPDATE smoke_allowance SET used_requests = used_requests + 1,"
            " held_micro_usd = held_micro_usd + ?, updated_at = ? WHERE id = 1",
            (amount_micro_usd, now),
        )
        return hold_id


def settle_hold(db_path: Path, *, hold_id: int, actual_micro_usd: int) -> None:
    """Convert a hold into its measured cost (actual may be below the hold)."""
    if actual_micro_usd < 0:
        raise ValueError("charge amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM smoke_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE smoke_holds SET status = 'charged', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE smoke_allowance SET held_micro_usd = held_micro_usd - ?,"
            " used_micro_usd = used_micro_usd + ?, updated_at = ? WHERE id = 1",
            (row[0], actual_micro_usd, now),
        )


def release_hold(db_path: Path, *, hold_id: int) -> None:
    """Release a hold for work that never dispatched (no worker capacity)."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM smoke_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE smoke_holds SET status = 'released', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE smoke_allowance SET held_micro_usd = held_micro_usd - ?,"
            " used_requests = used_requests - 1, updated_at = ? WHERE id = 1",
            (row[0], now),
        )


def abandon_hold(db_path: Path, *, hold_id: int) -> None:
    """Keep the full hold for work of unknown size (timeout/cancel/error)."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT amount_micro_usd FROM smoke_holds WHERE id = ? AND status = 'active'",
            (hold_id,),
        ).fetchone()
        if row is None:
            return
        conn.execute(
            "UPDATE smoke_holds SET status = 'charged', settled_at = ? WHERE id = ?",
            (now, hold_id),
        )
        conn.execute(
            "UPDATE smoke_allowance SET held_micro_usd = held_micro_usd - ?,"
            " used_micro_usd = used_micro_usd + ?, updated_at = ? WHERE id = 1",
            (row[0], row[0], now),
        )

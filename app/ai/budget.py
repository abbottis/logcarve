"""Concurrency-aware, durable model budget enforcement (T7).

Reservations and charges live in the ``ai_spend`` table and every
mutation runs inside a writer transaction, so simultaneous in-flight
requests serialize on the database lock: two workers cannot reserve
the same remaining allowance twice, and a restart can neither reset
nor double-spend outstanding reservations. Amounts are integer
micro-USD to avoid float drift. Recorded usage carries amounts and
day buckets only, never prompts or sensitive content.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.db.database import writer_transaction

MICRO_USD_PER_USD = 1_000_000


class BudgetExhausted(RuntimeError):
    """No further model spend is permitted under the configured limits."""

    def __init__(self, code: str, message: str, *, warned: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.warned = warned


def usd_to_micro(amount_usd: float) -> int:
    return max(0, round(amount_usd * MICRO_USD_PER_USD))


def micro_to_usd(amount_micro: int) -> float:
    return amount_micro / MICRO_USD_PER_USD


def _day_micro(conn: sqlite3.Connection, *, day: str) -> int:
    # Measured charges plus still-active reservations for one UTC day. A
    # converted reservation row (status 'charged') is excluded so its
    # replacement charge row is not counted twice.
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_micro_usd), 0) FROM ai_spend"
        " WHERE day = ? AND (kind = 'charge'"
        " OR (kind = 'reservation' AND status = 'active'))",
        (day,),
    ).fetchone()
    return int(row[0])


def _lifetime_micro(conn: sqlite3.Connection) -> int:
    # Cumulative across days: every measured charge plus every still
    # active reservation. UTC rollover resets the daily bucket but never
    # this lifetime total, so the global stop cannot be escaped by
    # waiting for midnight.
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_micro_usd), 0) FROM ai_spend"
        " WHERE kind = 'charge' OR (kind = 'reservation' AND status = 'active')"
    ).fetchone()
    return int(row[0])


def _read_micro(db_path: Path, query: str, day: str | None) -> int:
    from app.db.database import connect

    conn = connect(Path(db_path), read_only=True)
    try:
        if query == "day":
            assert day is not None
            return _day_micro(conn, day=day)
        return _lifetime_micro(conn)
    finally:
        conn.close()


def outstanding_micro_usd(db_path: Path, *, day: str) -> int:
    """Current outstanding spend (active reservations plus charges) for a day."""
    return _read_micro(db_path, "day", day)


def lifetime_micro_usd(db_path: Path) -> int:
    """Cumulative outstanding spend across all days (charges plus active)."""
    return _read_micro(db_path, "lifetime", None)


def reserve(
    db_path: Path,
    *,
    day: str,
    amount_micro_usd: int,
    daily_limit_micro_usd: int,
    stop_micro_usd: int,
    total_micro_usd: int,
    warn_micro_usd: int,
    investigation_id: str,
) -> tuple[int, bool]:
    """Atomically reserve bounded spend; raise BudgetExhausted when blocked.

    The daily limit binds only today's bucket; the stop and total caps
    bind the cumulative lifetime total across days, so a UTC rollover
    never resets the global stop. Returns the reservation id and whether
    the warning threshold is now reached. A zero or negative daily limit
    means no allowance at all.
    """
    if amount_micro_usd < 0:
        raise ValueError("reservation amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        today = _day_micro(conn, day=day)
        lifetime = _lifetime_micro(conn)
        if daily_limit_micro_usd <= 0 or today + amount_micro_usd > daily_limit_micro_usd:
            raise BudgetExhausted(
                "daily_limit_reached",
                "The daily AI usage allowance is exhausted.",
                warned=True,
            )
        if lifetime + amount_micro_usd > stop_micro_usd:
            raise BudgetExhausted(
                "stop_limit_reached",
                "The AI usage stop limit has been reached.",
                warned=True,
            )
        if lifetime + amount_micro_usd > total_micro_usd:
            raise BudgetExhausted(
                "budget_exhausted",
                "The total AI budget has been reached.",
                warned=True,
            )
        warned = lifetime + amount_micro_usd >= warn_micro_usd
        cursor = conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, investigation_id, created_at)"
            " VALUES (?, 'reservation', ?, 'active', ?, ?)",
            (day, amount_micro_usd, investigation_id, now),
        )
        reservation_id = cursor.lastrowid
        assert reservation_id is not None
        return reservation_id, warned


def release(db_path: Path, *, reservation_id: int) -> None:
    """Release an unused reservation without recording spend."""
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        conn.execute(
            "UPDATE ai_spend SET status = 'released', settled_at = ?"
            " WHERE id = ? AND kind = 'reservation' AND status = 'active'",
            (now, reservation_id),
        )


def charge(db_path: Path, *, reservation_id: int, actual_micro_usd: int) -> None:
    """Convert a reservation into a measured charge for the actual spend."""
    if actual_micro_usd < 0:
        raise ValueError("charge amounts must be non-negative")
    now = datetime.now(UTC).isoformat()
    with writer_transaction(Path(db_path)) as conn:
        row = conn.execute(
            "SELECT day, investigation_id FROM ai_spend"
            " WHERE id = ? AND kind = 'reservation' AND status = 'active'",
            (reservation_id,),
        ).fetchone()
        if row is None:
            return
        day, investigation_id = row
        conn.execute(
            "UPDATE ai_spend SET status = 'charged', settled_at = ? WHERE id = ?",
            (now, reservation_id),
        )
        conn.execute(
            "INSERT INTO ai_spend (day, kind, amount_micro_usd, status, investigation_id,"
            " created_at, settled_at) VALUES (?, 'charge', ?, 'charged', ?, ?, ?)",
            (day, actual_micro_usd, investigation_id, now, now),
        )

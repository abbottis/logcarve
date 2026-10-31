"""T7 budget tests: durable, concurrent, cumulative-across-days enforcement."""

import threading

import pytest

from app.ai import budget
from app.db.migrations_runner import migrate

DAY = "2026-10-31"
NEXT_DAY = "2026-11-01"
BIG = budget.usd_to_micro(1000.0)


def _db(tmp_path):
    db = tmp_path / "budget.sqlite3"
    migrate(db)
    return db


def _limits(**overrides):
    limits = {
        "daily_limit_micro_usd": budget.usd_to_micro(10.0),
        "stop_micro_usd": budget.usd_to_micro(140.0),
        "total_micro_usd": budget.usd_to_micro(150.0),
        "warn_micro_usd": budget.usd_to_micro(120.0),
    }
    limits.update(overrides)
    return limits


def test_reserve_charge_release_accounting(tmp_path):
    db = _db(tmp_path)
    rid, warned = budget.reserve(
        db, day=DAY, amount_micro_usd=100, investigation_id="a", **_limits()
    )
    assert not warned
    assert budget.outstanding_micro_usd(db, day=DAY) == 100
    budget.charge(db, reservation_id=rid, actual_micro_usd=40)
    # The converted reservation must not double-count its replacement charge.
    assert budget.outstanding_micro_usd(db, day=DAY) == 40
    assert budget.lifetime_micro_usd(db) == 40


def test_release_resets_without_spend(tmp_path):
    db = _db(tmp_path)
    rid, _ = budget.reserve(db, day=DAY, amount_micro_usd=100, investigation_id="a", **_limits())
    budget.release(db, reservation_id=rid)
    assert budget.outstanding_micro_usd(db, day=DAY) == 0
    assert budget.lifetime_micro_usd(db) == 0


def test_restart_keeps_ledger(tmp_path):
    db = _db(tmp_path)
    rid, _ = budget.reserve(db, day=DAY, amount_micro_usd=100, investigation_id="a", **_limits())
    # A new handle on the same file (restart / second worker) sees the same state.
    assert budget.outstanding_micro_usd(db, day=DAY) == 100
    budget.charge(db, reservation_id=rid, actual_micro_usd=100)
    assert budget.lifetime_micro_usd(db) == 100


def test_zero_daily_limit_blocks_everything(tmp_path):
    db = _db(tmp_path)
    with pytest.raises(budget.BudgetExhausted) as excinfo:
        budget.reserve(
            db,
            day=DAY,
            amount_micro_usd=1,
            investigation_id="a",
            **_limits(daily_limit_micro_usd=0),
        )
    assert excinfo.value.code == "daily_limit_reached"


def test_warn_flag_at_threshold(tmp_path):
    db = _db(tmp_path)
    _, warned = budget.reserve(
        db,
        day=DAY,
        amount_micro_usd=budget.usd_to_micro(120.0),
        investigation_id="a",
        **_limits(daily_limit_micro_usd=BIG, stop_micro_usd=BIG, total_micro_usd=BIG),
    )
    assert warned is True


def test_utc_rollover_resets_daily_but_not_global_stop(tmp_path):
    db = _db(tmp_path)
    limits = _limits(
        daily_limit_micro_usd=budget.usd_to_micro(50.0),
        stop_micro_usd=budget.usd_to_micro(60.0),
        total_micro_usd=budget.usd_to_micro(150.0),
    )
    rid, _ = budget.reserve(
        db, day=DAY, amount_micro_usd=budget.usd_to_micro(50.0), investigation_id="a", **limits
    )
    budget.charge(db, reservation_id=rid, actual_micro_usd=budget.usd_to_micro(50.0))
    # Next UTC day: the daily bucket is fresh, but the lifetime stop still binds.
    with pytest.raises(budget.BudgetExhausted) as excinfo:
        budget.reserve(
            db,
            day=NEXT_DAY,
            amount_micro_usd=budget.usd_to_micro(20.0),
            investigation_id="b",
            **limits,
        )
    assert excinfo.value.code == "stop_limit_reached"
    assert budget.outstanding_micro_usd(db, day=NEXT_DAY) == 0
    assert budget.lifetime_micro_usd(db) == budget.usd_to_micro(50.0)


def test_total_cap_binds_beyond_stop(tmp_path):
    db = _db(tmp_path)
    limits = _limits(
        daily_limit_micro_usd=BIG, stop_micro_usd=BIG, total_micro_usd=budget.usd_to_micro(5.0)
    )
    with pytest.raises(budget.BudgetExhausted) as excinfo:
        budget.reserve(
            db, day=DAY, amount_micro_usd=budget.usd_to_micro(6.0), investigation_id="a", **limits
        )
    assert excinfo.value.code == "budget_exhausted"


def test_simultaneous_reservations_cannot_double_spend(tmp_path):
    db = _db(tmp_path)
    limits = _limits(daily_limit_micro_usd=budget.usd_to_micro(10.0))
    results = []
    barrier = threading.Barrier(4)

    def _worker(index):
        barrier.wait()
        try:
            rid, _ = budget.reserve(
                db,
                day=DAY,
                amount_micro_usd=budget.usd_to_micro(10.0),
                investigation_id=f"w{index}",
                **limits,
            )
            results.append(rid)
        except budget.BudgetExhausted:
            results.append(None)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert results.count(None) == 3
    assert budget.outstanding_micro_usd(db, day=DAY) == budget.usd_to_micro(10.0)

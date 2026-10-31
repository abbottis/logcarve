"""T8 smoke allowance unit tests: lifetime caps, atomic holds, no reset.

Offline tests on scratch databases: no key, no network. Amounts and
counts only.
"""

import pytest

from app.ai import budget, smoke
from app.db.migrations_runner import migrate


def _db(tmp_path):
    db = tmp_path / "smoke.sqlite3"
    migrate(db)
    return db


def _init(db):
    return smoke.init_or_check(
        db, max_investigations=3, max_requests=12, max_micro_usd=budget.usd_to_micro(1.0)
    )


def test_first_use_records_caps_and_widening_refused(tmp_path):
    db = _db(tmp_path)
    state = _init(db)
    assert state["used_investigations"] == 0
    # Narrower caps remain usable; wider caps are refused outright.
    smoke.init_or_check(
        db, max_investigations=2, max_requests=5, max_micro_usd=budget.usd_to_micro(0.5)
    )
    with pytest.raises(smoke.SmokeRefused):
        smoke.init_or_check(
            db, max_investigations=4, max_requests=12, max_micro_usd=budget.usd_to_micro(1.0)
        )


def test_investigation_lifetime_cap(tmp_path):
    db = _db(tmp_path)
    _init(db)
    for _ in range(3):
        smoke.admit_investigation(db, investigation_id="i")
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_investigation(db, investigation_id="i4")


def test_request_cap_counts_failed_attempts_and_holds(tmp_path):
    db = _db(tmp_path)
    _init(db)
    holds = [
        smoke.admit_request(db, amount_micro_usd=10_000, investigation_id="i1") for _ in range(12)
    ]
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_request(db, amount_micro_usd=1, investigation_id="i1")
    # Settling a hold does not free a request slot: attempts are lifetime.
    smoke.settle_hold(db, hold_id=holds[0], actual_micro_usd=5_000)
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_request(db, amount_micro_usd=1, investigation_id="i1")


def test_cost_cap_binds_before_overspend(tmp_path):
    db = _db(tmp_path)
    smoke.init_or_check(db, max_investigations=3, max_requests=12, max_micro_usd=100_000)
    hold = smoke.admit_request(db, amount_micro_usd=60_000, investigation_id="i1")
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_request(db, amount_micro_usd=50_000, investigation_id="i1")
    # Settling below the hold frees the difference for later work.
    smoke.settle_hold(db, hold_id=hold, actual_micro_usd=10_000)
    hold2 = smoke.admit_request(db, amount_micro_usd=50_000, investigation_id="i1")
    # Unknown-size work keeps its full hold.
    smoke.abandon_hold(db, hold_id=hold2)
    state = smoke.init_or_check(db, max_investigations=3, max_requests=12, max_micro_usd=100_000)
    assert state["used_micro_usd"] == 60_000
    assert state["held_micro_usd"] == 0


def test_counters_survive_restart_without_reset(tmp_path):
    db = _db(tmp_path)
    _init(db)
    smoke.admit_investigation(db, investigation_id="i1")
    hold = smoke.admit_request(db, amount_micro_usd=30_000, investigation_id="i1")
    smoke.settle_hold(db, hold_id=hold, actual_micro_usd=20_000)
    # A "restart" is just a new connection: counters persist, nothing resets.
    state = smoke.init_or_check(
        db, max_investigations=3, max_requests=12, max_micro_usd=budget.usd_to_micro(1.0)
    )
    assert state["used_investigations"] == 1
    assert state["used_requests"] == 1
    assert state["used_micro_usd"] == 20_000


def test_narrower_caps_apply_atomically_without_refund(tmp_path):
    """R5: tightening to 1/1/5 must bind; spend is never refunded."""
    db = _db(tmp_path)
    _init(db)
    hold = smoke.admit_request(db, amount_micro_usd=3, investigation_id="i1")
    smoke.settle_hold(db, hold_id=hold, actual_micro_usd=3)
    smoke.init_or_check(db, max_investigations=1, max_requests=1, max_micro_usd=5)
    state = smoke.init_or_check(db, max_investigations=1, max_requests=1, max_micro_usd=5)
    assert (state["max_investigations"], state["max_requests"], state["max_micro_usd"]) == (1, 1, 5)
    assert state["used_micro_usd"] == 3
    smoke.admit_investigation(db, investigation_id="i2")
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_investigation(db, investigation_id="i3")
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_request(db, amount_micro_usd=1, investigation_id="i2")


def test_last_slot_single_winner(tmp_path):
    db = _db(tmp_path)
    smoke.init_or_check(
        db, max_investigations=3, max_requests=1, max_micro_usd=budget.usd_to_micro(1.0)
    )
    smoke.admit_request(db, amount_micro_usd=1_000, investigation_id="i1")
    with pytest.raises(smoke.SmokeRefused):
        smoke.admit_request(db, amount_micro_usd=1_000, investigation_id="i2")

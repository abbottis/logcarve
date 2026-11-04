"""Runtime allowance unit tests: explicit grant, caps, no reset.

Pure offline tests with temporary databases: no network, no keys,
no provider account.
"""

import pytest

from app.ai import allowance, budget
from app.ai.allowance import AllowanceRefused
from app.db.migrations_runner import migrate


def _db(tmp_path):
    db = tmp_path / "allowance.sqlite3"
    migrate(db)
    return db


def test_missing_grant_fails_closed(tmp_path):
    db = _db(tmp_path)
    assert allowance.status(db) is None
    with pytest.raises(AllowanceRefused) as exc:
        allowance.admit_investigation(db, investigation_id="i1")
    assert exc.value.code == "usage_not_authorized"
    with pytest.raises(AllowanceRefused):
        allowance.admit_request(db, amount_micro_usd=100, investigation_id="i1")


def test_grant_admit_settle_lifecycle(tmp_path):
    db = _db(tmp_path)
    snapshot = allowance.grant(db, max_investigations=2, max_requests=3, max_micro_usd=1_000_000)
    assert snapshot["max_investigations"] == 2
    assert allowance.status(db)["used_investigations"] == 0
    allowance.admit_investigation(db, investigation_id="i1")
    hold = allowance.admit_request(db, amount_micro_usd=100_000, investigation_id="i1")
    mid = allowance.status(db)
    assert mid["used_investigations"] == 1
    assert mid["held_micro_usd"] == 100_000
    allowance.settle_hold(db, hold_id=hold, actual_micro_usd=40_000)
    after = allowance.status(db)
    assert after["held_micro_usd"] == 0
    assert after["used_micro_usd"] == 40_000


def test_release_and_abandon_paths(tmp_path):
    db = _db(tmp_path)
    allowance.grant(db, max_investigations=5, max_requests=5, max_micro_usd=1_000_000)
    allowance.admit_investigation(db, investigation_id="i1")
    hold = allowance.admit_request(db, amount_micro_usd=100_000, investigation_id="i1")
    allowance.release_hold(db, hold_id=hold)
    assert allowance.status(db)["held_micro_usd"] == 0
    hold2 = allowance.admit_request(db, amount_micro_usd=100_000, investigation_id="i1")
    allowance.abandon_hold(db, hold_id=hold2)
    assert allowance.status(db)["used_micro_usd"] == 100_000


def test_caps_refuse_without_reset(tmp_path):
    db = _db(tmp_path)
    allowance.grant(db, max_investigations=1, max_requests=1, max_micro_usd=100)
    allowance.admit_investigation(db, investigation_id="i1")
    with pytest.raises(AllowanceRefused) as exc:
        allowance.admit_investigation(db, investigation_id="i2")
    assert exc.value.code == "investigation_cap_reached"
    with pytest.raises(AllowanceRefused):
        allowance.admit_request(db, amount_micro_usd=101, investigation_id="i1")
    # Failed admissions never consume the grant.
    assert allowance.status(db)["used_investigations"] == 1
    assert allowance.status(db)["used_micro_usd"] == 0


def test_grant_only_narrows_never_widens(tmp_path):
    db = _db(tmp_path)
    allowance.grant(db, max_investigations=2, max_requests=2, max_micro_usd=500)
    with pytest.raises(AllowanceRefused):
        allowance.grant(db, max_investigations=3, max_requests=2, max_micro_usd=500)
    narrowed = allowance.grant(db, max_investigations=1, max_requests=1, max_micro_usd=100)
    assert narrowed == {
        "max_investigations": 1,
        "max_requests": 1,
        "max_micro_usd": 100,
    }
    with pytest.raises(AllowanceRefused):
        allowance.grant(db, max_investigations=2, max_requests=1, max_micro_usd=100)


def test_negative_amounts_rejected(tmp_path):
    db = _db(tmp_path)
    allowance.grant(db, max_investigations=1, max_requests=1, max_micro_usd=100)
    with pytest.raises(ValueError):
        allowance.admit_request(db, amount_micro_usd=-1, investigation_id="i1")
    with pytest.raises(ValueError):
        allowance.settle_hold(db, hold_id=1, actual_micro_usd=-1)
    with pytest.raises(ValueError):
        allowance.grant(db, max_investigations=-1, max_requests=1, max_micro_usd=1)


def test_restart_keeps_grant_and_spend(tmp_path):
    db = _db(tmp_path)
    allowance.grant(db, max_investigations=2, max_requests=4, max_micro_usd=1_000)
    allowance.admit_investigation(db, investigation_id="i1")
    hold = allowance.admit_request(db, amount_micro_usd=400, investigation_id="i1")
    allowance.settle_hold(db, hold_id=hold, actual_micro_usd=250)
    # A fresh process view (new connections) sees the same counters.
    assert allowance.status(db)["used_micro_usd"] == 250
    assert allowance.status(db)["used_investigations"] == 1
    assert budget.lifetime_micro_usd(db) == 0  # unrelated ledger untouched

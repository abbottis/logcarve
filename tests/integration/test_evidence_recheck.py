"""Evidence provenance and recheck regression (synthetic fixtures only).

Covers the ANA-01/ANA-03/AUTH-01/PRIV-01 slice of
``docs/evidence-revalidation-2026-11-03.md``: envelopes carry compact
generation provenance plus a result digest; a stateless signed receipt
replays the EXACT original scope through the same deterministic tool
path; rotation/retention classify honestly; failures fail closed.
"""

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from app.ai import receipts
from app.ai.tools import definitions as tools
from app.analytics.rules import load_rules
from app.api.routes_chat import attach_evidence_receipts
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.retention import apply_retention
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
SECRET = "synthetic-test-session-secret"
EXTRA_LINE = (
    b'203.0.113.9 - - [27/Oct/2026:12:30:00 +0000] "GET /extra HTTP/1.1"'
    b' 200 12 "-" "synthetic-agent/1.0"\n'
)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", SECRET)
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    db = tmp_path / "evidence.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return {"db": db, "root": root, "rules": rules}


def _args(**overrides):
    base = {"site_id": "default", "time_from": FROM.isoformat(), "time_to": TO.isoformat()}
    base.update(overrides)
    return base


def _envelope(env, name="get_summary", observed=NOW, **overrides):
    conn = connect(env["db"], read_only=True)
    try:
        return tools.execute_tool(
            conn,
            env["rules"],
            name=name,
            arguments=_args(**overrides),
            tool_call_id="tc1",
            observation_time=observed,
        )
    finally:
        conn.close()


def _receipt_for(envelope):
    return receipts.sign_receipt(
        receipts.receipt_payload(
            tool=envelope["tool"],
            filters=envelope["filters"],
            digest=envelope["result_digest"],
            provenance=envelope["provenance"],
            observation_time=envelope["observation_time"],
        ),
        secret=SECRET,
    )


def _client(env):
    from app.main import create_app

    return TestClient(create_app(db_path=env["db"], secure_cookies=False))


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _recheck(client, csrf, payload):
    return client.post(
        "/api/v1/chat/evidence/recheck", json=payload, headers={"X-CSRF-Token": csrf}
    )


def test_envelope_carries_provenance_and_digest(env):
    envelope = _envelope(env)
    assert isinstance(envelope["result_digest"], str) and len(envelope["result_digest"]) == 64
    assert envelope["result_digest"] == receipts.result_digest(envelope["result"])
    provenance = envelope["provenance"]
    assert provenance["site_id"] == "default"
    assert provenance["result_digest"] == envelope["result_digest"]
    assert provenance["unique_events"] == envelope["coverage"]["unique_events"] > 0
    assert provenance["imports_truncated"] is False
    heads = {entry["source_id"]: entry for entry in provenance["sources"]}
    assert heads["example-combined"]["import_head_id"] == 1
    # No raw internals travel with provenance.
    assert "file_fingerprint" not in receipts.canonical_json_bytes(provenance).decode()
    assert "203.0.113" not in receipts.canonical_json_bytes(provenance).decode()


def test_recheck_current_on_unchanged_replay(env):
    envelope = _envelope(env)
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": _receipt_for(envelope)})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "current"
    assert body["result_match"] is True
    assert body["generation_changed"] is False
    assert body["original_observation_time"] == envelope["observation_time"]
    assert body["observation_time"] != envelope["observation_time"]
    assert body["href"].startswith("/?site=default")
    assert body["coverage"]["unique_events"] == envelope["coverage"]["unique_events"]


def test_recheck_changed_after_rotation_new_generation(env):
    envelope = _envelope(env)
    with open(env["root"] / "access.log", "ab") as handle:
        handle.write(EXTRA_LINE)
    run_import(
        env["db"],
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=env["root"],
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "changed"
    assert body["result_match"] is False
    assert body["generation_changed"] is True
    assert body["coverage"]["unique_events"] > envelope["coverage"]["unique_events"]
    # The source file under test grew; the checked-in fixture is untouched.
    assert (
        EXTRA_LINE
        not in (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )


def test_recheck_unavailable_after_retention(env):
    envelope = _envelope(env)
    live = env["root"] / "access.log"
    before = hashlib.sha256(live.read_bytes()).hexdigest()
    with writer_transaction(env["db"]) as conn:
        deleted = apply_retention(conn, days=1, now=datetime(2027, 1, 1, tzinfo=UTC))
    assert deleted > 0
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "unavailable"
    assert body["result_match"] is False
    assert body["coverage"]["unique_events"] == 0
    # Retention plus recheck only touch owned rows: source bytes are intact.
    assert hashlib.sha256(live.read_bytes()).hexdigest() == before


def test_recheck_changed_after_partial_retention_source_bytes_intact(env):
    envelope = _envelope(env)
    live = env["root"] / "access.log"
    before = hashlib.sha256(live.read_bytes()).hexdigest()
    total = envelope["coverage"]["unique_events"]
    assert total > 0
    # Cutoff 2026-10-27T10:00Z keeps the later fixture events only.
    with writer_transaction(env["db"]) as conn:
        deleted = apply_retention(conn, days=1, now=datetime(2026, 10, 28, 10, 0, tzinfo=UTC))
    assert 0 < deleted < total
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "changed"
    assert body["result_match"] is False
    surviving = body["coverage"]["unique_events"]
    assert 0 < surviving < total
    assert surviving == total - deleted
    assert hashlib.sha256(live.read_bytes()).hexdigest() == before


def test_recheck_current_new_generation_after_run_follow_rotation(env):
    """Genuine rotation: rename the live file, follow the new generation.

    The recorded window keeps resolving exactly (same digest), while the
    follow/rotation generation heads move. New records land strictly
    outside the recorded window so only provenance moves, not content.
    """
    from app.db.follow import run_follow

    # get_security_findings carries a strictly window-scoped result: the
    # summary/timeseries envelopes embed source-wide import stats that
    # legitimately move with any new import activity.
    envelope = _envelope(env, name="get_security_findings")
    assert envelope["provenance"]["sources"][0]["generation_seq"] is None
    live = env["root"] / "access.log"
    live.rename(env["root"] / "access.log.1")
    live.write_bytes(
        b'203.0.113.9 - - [29/Oct/2026:12:30:00 +0000] "GET /extra HTTP/1.1"'
        b' 200 12 "-" "synthetic-agent/1.0"\n'
    )
    result = run_follow(
        env["db"],
        source=SourceConfig(
            source_id="example-combined",
            format_id="nginx_combined",
            allowed_root=env["root"],
            relative_path="access.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
        max_polls=2,
        poll_interval_s=0,
        # External rotation: the replacement file shares no prefix with
        # the earlier batch import, so follow starts a fresh generation
        # from offset 0 (no duplicated bytes: the new file holds only
        # the out-of-window record).
        fresh_start=True,
    )
    assert result.status == "completed", result.error_summary
    assert result.records_inserted == 1
    new_hash = hashlib.sha256(live.read_bytes()).hexdigest()
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    # Original evidence still resolves; only generation/provenance moved.
    assert body["status"] == "current"
    assert body["result_match"] is True
    assert body["generation_changed"] is True
    assert body["coverage"]["unique_events"] == envelope["coverage"]["unique_events"]
    new_sources = body["provenance"]["sources"]
    assert new_sources[0]["generation_seq"] == 1
    assert new_sources[0]["generation_id"] is not None
    # The replay is a pure read: the rotated source bytes are untouched.
    assert hashlib.sha256(live.read_bytes()).hexdigest() == new_hash


def test_same_count_different_evidence_digests_differ():
    first = {"totals": {"requests": 2}, "agents": ["a/1.0"]}
    second = {"totals": {"requests": 2}, "agents": ["b/2.0"]}
    assert receipts.result_digest(first) != receipts.result_digest(second)


def test_tampered_receipt_fails_closed(env):
    envelope = _envelope(env)
    receipt = _receipt_for(envelope)
    tampered = receipt[:-1] + ("0" if receipt[-1] != "0" else "1")
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": tampered})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_receipt"


def test_unknown_tool_receipt_fails_closed(env):
    envelope = _envelope(env)
    forged = receipts.sign_receipt(
        receipts.receipt_payload(
            tool="run_sql",
            filters=envelope["filters"],
            digest=envelope["result_digest"],
            provenance=envelope["provenance"],
            observation_time=envelope["observation_time"],
        ),
        secret=SECRET,
    )
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": forged})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_tool"


def test_foreign_scope_receipt_fails_closed(env):
    with writer_transaction(env["db"]) as conn:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("other", "Other site", "other.example.org", "UTC", NOW.isoformat()),
        )
    envelope = _envelope(env)
    forged_filters = dict(envelope["filters"])
    forged_filters["site_id"] = "other"
    forged_filters["source_id"] = "example-combined"
    forged = receipts.sign_receipt(
        receipts.receipt_payload(
            tool=envelope["tool"],
            filters=forged_filters,
            digest=envelope["result_digest"],
            provenance=envelope["provenance"],
            observation_time=envelope["observation_time"],
        ),
        secret=SECRET,
    )
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": forged})
    assert response.status_code == 403
    assert response.json()["code"] in ("forbidden_site", "forbidden_source")


def test_recheck_requires_session_csrf_and_rejects_bearers(env):
    from app.auth.tokens import issue_token

    envelope = _envelope(env)
    receipt = _receipt_for(envelope)
    client = _client(env)
    assert _recheck(client, "csrf-without-session", {"receipt": receipt}).status_code == 401
    csrf = _login(client)
    bare = _client(env)
    _login(bare)
    assert bare.post("/api/v1/chat/evidence/recheck", json={"receipt": receipt}).status_code == 403
    with writer_transaction(env["db"]) as conn:
        _, token = issue_token(conn, name="api", site_id="default")
    token_client = _client(env)
    response = token_client.post(
        "/api/v1/chat/evidence/recheck",
        json={"receipt": receipt},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert _recheck(client, csrf, {"receipt": receipt}).status_code == 200


def test_legacy_evidence_without_receipt_is_unverified(env):
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"tool": "get_summary", "filters": _args()})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unverified"
    assert body["reason"] == "legacy_no_receipt"
    # The untrusted client filters object is never echoed back.
    assert body["filters"] is None
    assert _recheck(client, csrf, {}).status_code == 400


def test_legacy_evidence_never_echoes_unbounded_client_filters(env):
    client = _client(env)
    csrf = _login(client)
    junk = {f"junk-{index}": "x" * 500 for index in range(50)}
    response = _recheck(client, csrf, {"tool": "get_summary", "filters": junk})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unverified"
    assert body["filters"] is None
    assert "junk-0" not in response.text


@pytest.mark.parametrize("bad", ["abc.é", "é.abc", "", ".", "...", "a.b", "!!.!!"])
def test_verify_receipt_rejects_malformed_signatures_without_raising(bad):
    assert receipts.verify_receipt(bad, secret=SECRET) is None


@pytest.mark.parametrize("bad", [None, 123, b"abc.def", ["x"], {"receipt": 1}])
def test_verify_receipt_rejects_odd_types_without_raising(bad):
    assert receipts.verify_receipt(bad, secret=SECRET) is None


def test_verify_receipt_rejects_oversize_and_bad_shapes():
    assert receipts.verify_receipt("a" * 70000 + "." + "b" * 64, secret=SECRET) is None
    base = {
        "v": "ev-receipt-1",
        "tool": "get_summary",
        "filters": {"site_id": "default"},
        "result_digest": "0" * 64,
        "provenance": {},
        "observation_time": NOW.isoformat(),
    }
    assert (
        receipts.verify_receipt(
            receipts.sign_receipt({**base, "extra": 1}, secret=SECRET), secret=SECRET
        )
        is None
    )
    assert (
        receipts.verify_receipt(
            receipts.sign_receipt({**base, "v": "ev-receipt-0"}, secret=SECRET),
            secret=SECRET,
        )
        is None
    )
    assert (
        receipts.verify_receipt(
            receipts.sign_receipt({**base, "tool": ""}, secret=SECRET), secret=SECRET
        )
        is None
    )
    assert (
        receipts.verify_receipt(
            receipts.sign_receipt({**base, "result_digest": "xyz"}, secret=SECRET),
            secret=SECRET,
        )
        is None
    )
    assert (
        receipts.verify_receipt(
            receipts.sign_receipt(["not", "a", "dict"], secret=SECRET), secret=SECRET
        )
        is None
    )
    # Corrupting one body character keeps the failure a clean None.
    good = receipts.sign_receipt(base, secret=SECRET)
    body, _, sig = good.rpartition(".")
    assert receipts.verify_receipt("!" + body[1:] + "." + sig, secret=SECRET) is None
    assert receipts.verify_receipt(body + ".é", secret=SECRET) is None


def test_recheck_malformed_receipt_returns_400_with_request_id(env):
    envelope = _envelope(env)
    receipt = _receipt_for(envelope)
    client = _client(env)
    csrf = _login(client)
    for bad in ("abc.é", "!!!.def", "a.b", receipt[:-1] + "é"):
        response = _recheck(client, csrf, {"receipt": bad})
        assert response.status_code == 400, bad
        body = response.json()
        assert body["code"] == "invalid_receipt"
        assert body["request_id"] == response.headers.get("X-Request-ID")


def test_recheck_rejects_unknown_fields(env):
    envelope = _envelope(env)
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": _receipt_for(envelope), "unexpected": 1})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"


def test_recheck_ignores_client_filters_alongside_receipt(env):
    envelope = _envelope(env)
    forged = dict(envelope["filters"])
    forged["site_id"] = "other"
    client = _client(env)
    csrf = _login(client)
    # Client scope riding alongside a receipt must not broaden execution.
    response = _recheck(client, csrf, {"receipt": _receipt_for(envelope), "filters": forged})
    assert response.status_code == 200
    assert response.json()["status"] == "current"


def test_recheck_missing_generation_table_returns_503_not_current(env):
    envelope = _envelope(env)
    receipt = _receipt_for(envelope)
    with writer_transaction(env["db"]) as conn:
        conn.execute("DROP TABLE follow_generations")
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": receipt})
    # Metadata errors must never read as fresh/changed generation claims.
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "store_unavailable"
    assert body["request_id"] == response.headers.get("X-Request-ID")
    assert "follow_generations" not in response.text
    assert "OperationalError" not in response.text


def test_provenance_helper_propagates_store_errors(env):
    from app.analytics import provenance as provenance_mod

    with writer_transaction(env["db"]) as conn:
        conn.execute("DROP TABLE follow_generations")
    conn = connect(env["db"], read_only=True)
    try:
        with pytest.raises(sqlite3.Error):
            provenance_mod.build_provenance(
                conn,
                site_id="default",
                source_id="example-combined",
                unique_events=1,
                observed_min=None,
                observed_max=None,
                imports_truncated=False,
                digest="x",
            )
    finally:
        conn.close()


def test_recheck_withholds_current_when_source_listing_capped(env):
    from app.analytics.provenance import MAX_PROVENANCE_SOURCES

    with writer_transaction(env["db"]) as conn:
        for index in range(MAX_PROVENANCE_SOURCES + 6):
            conn.execute(
                "INSERT INTO log_sources (id, site_id, server_type, format_id, path_alias)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    f"extra-{index:03d}",
                    "default",
                    "nginx",
                    "nginx_combined",
                    f"extra-{index:03d}.log",
                ),
            )
    envelope = _envelope(env)
    assert len(envelope["provenance"]["sources"]) == MAX_PROVENANCE_SOURCES
    assert envelope["provenance"]["complete"] is False
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "unverified"
    assert body["reason"] == "provenance_incomplete"


@pytest.mark.parametrize("marker", ["__missing__", None, "true", "false", 1, 0, 0.0, False])
def test_recheck_withholds_current_when_legacy_receipt_lacks_explicit_complete(env, marker):
    """A signed legacy receipt without ``complete is True`` never reads current.

    Unknown completeness must not become a positive claim: a missing,
    null, string, numeric or false marker on the signed (old) provenance
    reports ``unverified``/``provenance_incomplete`` even though the
    signature itself is valid and the fresh replay is complete.
    """
    envelope = _envelope(env)
    assert envelope["provenance"]["complete"] is True
    provenance = dict(envelope["provenance"])
    if marker == "__missing__":
        provenance.pop("complete", None)
    else:
        provenance["complete"] = marker
    receipt = receipts.sign_receipt(
        receipts.receipt_payload(
            tool=envelope["tool"],
            filters=envelope["filters"],
            digest=envelope["result_digest"],
            provenance=provenance,
            observation_time=envelope["observation_time"],
        ),
        secret=SECRET,
    )
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": receipt})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "unverified"
    assert body["reason"] == "provenance_incomplete"


def test_recheck_store_open_failure_returns_structured_503(env, monkeypatch):
    from app.api import deps

    real_connect = deps.connect
    armed = {"on": False}

    def _failing(db_path, **kwargs):
        if armed["on"]:
            raise sqlite3.OperationalError("synthetic open failure")
        return real_connect(db_path, **kwargs)

    monkeypatch.setattr(deps, "connect", _failing)
    receipt = _receipt_for(_envelope(env))
    client = _client(env)
    csrf = _login(client)
    armed["on"] = True
    response = _recheck(client, csrf, {"receipt": receipt})
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "store_unavailable"
    assert body["request_id"] == response.headers.get("X-Request-ID")
    assert "synthetic" not in response.text
    assert "OperationalError" not in response.text


def test_recheck_plain_value_error_is_not_store_unavailable(env, monkeypatch):
    from app.ai.tools import definitions

    def _boom(*args, **kwargs):
        raise ValueError("synthetic validation failure")

    receipt = _receipt_for(_envelope(env))
    monkeypatch.setattr(definitions, "execute_tool", _boom)
    client = _client(env)
    csrf = _login(client)
    response = _recheck(client, csrf, {"receipt": receipt})
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_arguments"


def test_recheck_runs_with_ai_disabled_and_no_model_calls(env):
    from app.main import create_app

    envelope = _envelope(env)
    client = TestClient(create_app(db_path=env["db"], secure_cookies=False))
    csrf = _login(client)
    disabled = client.post(
        "/api/v1/chat/ask", json={"question": "q"}, headers={"X-CSRF-Token": csrf}
    )
    assert disabled.status_code in (400, 409)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "current"


def test_chat_receipt_attach_keeps_valid_and_marks_legacy():
    good = {
        "tool": "get_summary",
        "filters": {"site_id": "default"},
        "result_digest": "0" * 64,
        "provenance": {"sources": []},
        "observation_time": NOW.isoformat(),
    }
    legacy = {"tool": "get_summary", "filters": {"site_id": "default"}}
    attach_evidence_receipts([good, legacy, "not-a-dict"], secret_value=SECRET)
    assert receipts.verify_receipt(good["receipt"], secret=SECRET)["tool"] == "get_summary"
    assert "receipt" not in legacy

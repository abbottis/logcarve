"""Evidence provenance and recheck regression (synthetic fixtures only).

Covers the ANA-01/ANA-03/AUTH-01/PRIV-01 slice of
``docs/evidence-revalidation-2026-11-03.md``: envelopes carry compact
generation provenance plus a result digest; a stateless signed receipt
replays the EXACT original scope through the same deterministic tool
path; rotation/retention classify honestly; failures fail closed.
"""

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
    with writer_transaction(env["db"]) as conn:
        deleted = apply_retention(conn, days=1, now=datetime(2027, 1, 1, tzinfo=UTC))
    assert deleted > 0
    client = _client(env)
    csrf = _login(client)
    body = _recheck(client, csrf, {"receipt": _receipt_for(envelope)}).json()
    assert body["status"] == "unavailable"
    assert body["result_match"] is False
    assert body["coverage"]["unique_events"] == 0


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
    assert response.json()["status"] == "unverified"
    assert _recheck(client, csrf, {}).status_code == 400


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

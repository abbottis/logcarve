"""T7 tool tests: allowlist, validation, scope and hostile log-derived input."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai.tools import definitions as tools
from app.analytics.rules import load_rules
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)
ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "combined" / "nginx_combined.txt").read_bytes()
    )
    (root / "evil.log").write_bytes(
        (ROOT / "tests" / "fixtures" / "adversarial" / "combined_mixed.txt").read_bytes()
    )
    db = tmp_path / "tools.sqlite3"
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
    run_import(
        db,
        source=SourceConfig(
            source_id="evil-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="evil.log",
        ),
        site_id="default",
        site_name="s",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="evil.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("other", "Other site", "other.example.org", "UTC", NOW.isoformat()),
        )
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return db, rules


def _args(**overrides):
    base = {"site_id": "default", "time_from": FROM.isoformat(), "time_to": TO.isoformat()}
    base.update(overrides)
    return base


def _run(store, name, args):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        return tools.execute_tool(conn, rules, name=name, arguments=args, tool_call_id="tc1")
    finally:
        conn.close()


def test_all_allowlisted_tools_execute(store):
    for name in tools.TOOL_NAMES:
        envelope = _run(store, name, _args())
        assert envelope["tool_call_id"] == "tc1"
        assert envelope["filters"]["site_id"] == "default"
        assert "observation_time" in envelope


def test_unknown_tool_rejected(store):
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "run_sql", _args())
    assert excinfo.value.code == "unknown_tool"


def test_extra_arguments_and_oversized_limit_rejected(store):
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "get_summary", _args(sql="SELECT 1"))
    assert excinfo.value.code == "invalid_arguments"
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "get_summary", _args(limit=100000))
    assert excinfo.value.code == "invalid_arguments"


def test_cross_site_and_unknown_scope_rejected(store):
    # A source bound to "default" cannot be read through another site.
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "get_summary", _args(site_id="other", source_id="evil-source"))
    assert excinfo.value.code == "forbidden_source"
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "get_summary", _args(site_id="no-such-site"))
    assert excinfo.value.code == "forbidden_site"
    with pytest.raises(tools.ToolError) as excinfo:
        _run(store, "get_summary", _args(source_id="evil-source-x"))
    assert excinfo.value.code == "forbidden_source"


def test_hostile_log_content_yields_data_not_execution(store):
    envelope = _run(store, "get_crawler_claims", _args(source_id="evil-source"))
    assert envelope["filters"]["site_id"] == "default"
    envelope = _run(store, "get_security_findings", _args(source_id="evil-source"))
    assert isinstance(envelope["result"]["items"], list)
    envelope = _run(store, "get_top_paths", _args(source_id="evil-source"))
    assert envelope["result"]["total_groups"] >= 0

"""T3b corrections: snapshot ownership, trusted comparison, client safety.

Offline ONLY (synthetic fixture, temporary stores, fake transports,
blocked sockets): proves the four T3b findings are fixed without
loosening budgets or leaking private data.

- Tool snapshot ownership: owned ``BEGIN`` commits before ``RETURN``
  on success, rolls back on failure, caller-owned transactions stay
  intact, concurrent uncommitted writers stay invisible.
- Trusted comparison: the model ``comparison`` report compares equal
  halves INSIDE the selected window; rows just outside both parent
  edges are never read, hostile model times are overridden, and the
  exact current/baseline scopes travel with explicit definitions.
- Client downloads: bounded streaming verification (no unbounded
  ``read()``), exclusive ``0600`` outputs that refuse existing
  targets (including symlinks), run-owned partial cleanup on every
  failure, and cross-origin/downgrade redirect refusal.
- Projection honesty: slow-endpoint evidence carries the server
  ranking (``avg_desc``); comparison evidence carries both windows
  plus the inside-split definition.

This NEVER labels real-AI acceptance passed: fake transports only,
no production key, account or paid call. Temporary stores only.
"""

import http.client
import io
import json
import os
import sqlite3
import stat
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

import clients.logcarve_api_client as client_mod
from app.ai import egress as egress_mod
from app.ai.service import _execute_bounded_tool
from app.ai.tools import definitions as tools
from app.analytics.rules import load_rules
from app.analytics.service import split_trusted_window_filter
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"t3b-corrections-test-key"
NOW = datetime(2026, 10, 29, 12, 0, 0, tzinfo=UTC)
FROM = datetime(2026, 10, 27, 10, 0, tzinfo=UTC)
TO = datetime(2026, 10, 27, 11, 0, tzinfo=UTC)
MID = FROM + (TO - FROM) / 2


def _line(ip, stamp, method, path, status):
    return (
        f'{ip} - - [{stamp} +0000] "{method} {path} HTTP/1.1" {status} 10 "-" "Browser/1.0"\n'
    ).encode()


def _xline(ip, stamp, method, path, status, rt):
    # nginx_extended: host cache rt mime tls upstream after the agent.
    return (
        f"{ip} - - [{stamp} +0000] "
        f'"{method} {path} HTTP/1.1" {status} 10 "-" "Browser/1.0" '
        f'example.org HIT {rt} text/html TLSv1.3 "-"\n'
    ).encode()


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b"".join(
            [
                # Just outside the parent window: never read by comparison.
                _line("198.51.100.9", "27/Oct/2026:09:59:00", "GET", "/outside-before", 200),
                _line("198.51.100.7", "27/Oct/2026:10:10:00", "GET", "/first-half", 200),
                _line("198.51.100.7", "27/Oct/2026:10:20:00", "GET", "/first-half", 200),
                _line("198.51.100.8", "27/Oct/2026:10:40:00", "GET", "/second-half", 200),
                _line("198.51.100.8", "27/Oct/2026:10:50:00", "GET", "/second-half", 200),
                _line("198.51.100.9", "27/Oct/2026:11:01:00", "GET", "/outside-after", 200),
            ]
        )
    )
    db = tmp_path / "t3b.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="s1",
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
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return db, rules


@pytest.fixture
def measured_store(tmp_path):
    """Extended-format store with measured timing for ranking evidence."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b"".join(
            [
                _xline(
                    "198.51.100.7",
                    "27/Oct/2026:10:05:00",
                    "GET",
                    "/measured-fast",
                    200,
                    "0.010",
                ),
                _xline(
                    "198.51.100.7",
                    "27/Oct/2026:10:06:00",
                    "GET",
                    "/measured-slow",
                    200,
                    "0.900",
                ),
            ]
        )
    )
    db = tmp_path / "t3b-measured.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="s1",
            format_id="nginx_extended",
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
    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    return db, rules


def _args(**overrides):
    base = {"site_id": "default", "time_from": FROM.isoformat(), "time_to": TO.isoformat()}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Snapshot ownership
# ---------------------------------------------------------------------------


def test_owned_snapshot_commits_before_return(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        assert conn.in_transaction is False
        envelope = tools.execute_tool(
            conn, rules, name="get_summary", arguments=_args(), tool_call_id="tc1"
        )
        assert envelope["tool"] == "get_summary"
        # The owned snapshot closed before RETURN: no dangling transaction.
        assert conn.in_transaction is False
        # The connection stays usable for a second owned read.
        envelope2 = tools.execute_tool(
            conn, rules, name="get_summary", arguments=_args(), tool_call_id="tc2"
        )
        assert envelope2["tool_call_id"] == "tc2"
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_caller_owned_transaction_stays_intact(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        conn.execute("BEGIN")
        assert conn.in_transaction is True
        envelope = tools.execute_tool(
            conn, rules, name="get_summary", arguments=_args(), tool_call_id="tc1"
        )
        assert envelope["filters"]["site_id"] == "default"
        # Caller-owned: the tool neither commits nor rolls back our work.
        assert conn.in_transaction is True
        conn.execute("ROLLBACK")
        assert conn.in_transaction is False
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()


def test_owned_snapshot_rolls_back_on_error(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        assert conn.in_transaction is False
        with pytest.raises(tools.ToolError) as excinfo:
            tools.execute_tool(
                conn,
                rules,
                name="get_summary",
                arguments=_args(site_id="no-such-site"),
                tool_call_id="tc1",
            )
        assert excinfo.value.code == "forbidden_site"
        assert conn.in_transaction is False
        # The store still serves after the rolled-back failure.
        envelope = tools.execute_tool(
            conn, rules, name="get_summary", arguments=_args(), tool_call_id="tc2"
        )
        assert envelope["tool"] == "get_summary"
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_concurrent_uncommitted_writer_stays_invisible(store):
    db, rules = store
    writer = connect(db)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("ghost", "Ghost", "ghost.example.org", "UTC", NOW.isoformat()),
        )
        reader = connect(db, read_only=True)
        try:
            # The ghost site is uncommitted: the owned reader snapshot
            # cannot see it and fails closed, then releases cleanly.
            with pytest.raises(tools.ToolError) as excinfo:
                tools.execute_tool(
                    reader,
                    rules,
                    name="get_summary",
                    arguments=_args(site_id="ghost"),
                    tool_call_id="tc1",
                )
            assert excinfo.value.code == "forbidden_site"
            assert reader.in_transaction is False
        finally:
            reader.close()
        writer.execute("ROLLBACK")
    finally:
        try:
            writer.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        writer.close()
    # After rollback the ghost is gone and the store still serves.
    conn = connect(db, read_only=True)
    try:
        envelope = tools.execute_tool(
            conn, rules, name="get_summary", arguments=_args(), tool_call_id="tc2"
        )
        assert conn.in_transaction is False
        assert envelope["tool"] == "get_summary"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 2. Trusted comparison window
# ---------------------------------------------------------------------------


def test_split_halves_stay_inside_parent(store):
    db, _rules = store
    conn = connect(db, read_only=True)
    try:
        current, previous = split_trusted_window_filter(
            tools._filter(tools.ReportArguments(**_args(report="comparison")))
        )
        assert previous.window.time_from == FROM
        assert previous.window.time_to == MID
        assert current.window.time_from == MID
        assert current.window.time_to == TO
    finally:
        conn.close()


def test_model_comparison_never_reads_outside_edges(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        envelope = tools.execute_tool(
            conn, rules, name="get_report", arguments=_args(report="comparison"), tool_call_id="tc1"
        )
        result = envelope["result"]
        assert result["previous_window"] == {
            "time_from": FROM.isoformat(),
            "time_to": MID.isoformat(),
        }
        assert result["current_window"] == {
            "time_from": MID.isoformat(),
            "time_to": TO.isoformat(),
        }
        assert result["parent_window"] == {
            "time_from": FROM.isoformat(),
            "time_to": TO.isoformat(),
        }
        by_name = {m["name"]: m for m in result["metrics"]}
        # Outside-edge rows (/outside-before, /outside-after) are never
        # read: each half holds exactly its two inside rows.
        assert by_name["requests"]["previous"] == 2
        assert by_name["requests"]["current"] == 2
    finally:
        conn.close()


def test_model_comparison_overrides_hostile_times(store):
    db, rules = store
    out = _execute_bounded_tool(
        db,
        rules,
        "get_report",
        {
            "report": "comparison",
            "site_id": "other",
            "time_from": "2020-01-01T00:00:00+00:00",
            "time_to": "2020-01-02T00:00:00+00:00",
        },
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        tool_index=1,
        investigation_id="t3b-scope-01",
        observation_time=NOW,
    )
    filters = out["envelope"]["filters"]
    assert filters["site_id"] == "default"
    assert filters["time_from"] == FROM.isoformat()
    assert filters["time_to"] == TO.isoformat()
    result = out["envelope"]["result"]
    assert result["previous_window"]["time_from"] == FROM.isoformat()
    assert result["previous_window"]["time_to"] == MID.isoformat()
    assert result["current_window"]["time_from"] == MID.isoformat()
    assert result["current_window"]["time_to"] == TO.isoformat()
    assert "inside" in result["definition"]


def test_unsplittable_window_fails_closed(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        odd_from = datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC)
        odd_to = datetime(2026, 10, 27, 10, 0, 0, 1, tzinfo=UTC)  # 1 microsecond
        with pytest.raises(tools.ToolError):
            tools.execute_tool(
                conn,
                rules,
                name="get_report",
                arguments={
                    "site_id": "default",
                    "time_from": odd_from.isoformat(),
                    "time_to": odd_to.isoformat(),
                    "report": "comparison",
                },
                tool_call_id="tc1",
            )
        assert conn.in_transaction is False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 3. Bounded client downloads, output ownership, redirects
# ---------------------------------------------------------------------------


class _FakeHeaders(dict):
    pass


class _FakeResponse:
    """Chunked body double: refuses unbounded ``read()`` when strict."""

    def __init__(self, body: bytes, headers: dict, *, strict: bool = True):
        self._body = io.BytesIO(body)
        self.headers = headers
        self._strict = strict

    def read(self, size: int = -1) -> bytes:
        if self._strict:
            assert size is not None and size >= 0, "unbounded read() is forbidden"
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, response: _FakeResponse):
        self.response = response
        self.requests: list = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        return self.response


def _export_headers(n: int) -> dict:
    return {"X-Logcarve-Export-Schema": "export/1", "X-Logcarve-Export-Rows": str(n)}


def test_verify_refuses_unbounded_reads_and_counts_streamed_csv(tmp_path, monkeypatch):
    import builtins

    real_open = builtins.open

    class _GuardedHandle:
        """Proxy: only bounded read/readline; iteration always raises."""

        def __init__(self, raw):
            self._raw = raw

        def read(self, size: int = -1):
            assert size is not None and size >= 0, "unbounded read() is forbidden"
            return self._raw.read(size)

        def readline(self, size: int = -1):
            assert size is not None and size >= 0, "unbounded readline() is forbidden"
            assert size <= client_mod._CSV_READLINE_CHARS, "oversized readline() bound"
            return self._raw.readline(size)

        def __iter__(self):
            raise AssertionError("bare handle iteration is forbidden")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._raw.__exit__(*exc)

        def close(self):
            return self._raw.close()

    def refusing_open(path, mode="r", *args, **kwargs):
        handle = real_open(path, mode, *args, **kwargs)
        if "r" in mode:
            return _GuardedHandle(handle)
        return handle

    # Any unbounded file read (or bare iteration, which hides an
    # unbounded physical-line read behind the iterator protocol)
    # inside verification raises here instead of silently buffering:
    # success below proves bounded access.
    monkeypatch.setattr("builtins.open", refusing_open)
    dest = tmp_path / "ok.csv"
    # Quoted newline plus multibyte text: one logical record, split
    # across any chunking, never two rows.
    dest.write_text('path,note\n"/a","line1\nline2 ✓"\n/b,plain\n', encoding="utf-8")
    summary = client_mod._verify_export_file(str(dest), "csv", 2)
    assert summary == {"path": str(dest), "format": "csv", "rows": 2, "complete": True}


def test_verify_json_incremental_across_chunk_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(client_mod, "VERIFY_CHUNK_BYTES", 7)
    body = json.dumps(
        {
            "metadata": {"schema_version": "export/1", "row_count": 3},
            "rows": [
                {"n": 5, "z": None, "formula": "'=1+1"},
                {"n": 0, "z": None, "text": "✓ multibyte ✓"},
                {"n": -3, "z": None, "path": "/b"},
            ],
            "complete": True,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    dest = tmp_path / "ok.json"
    dest.write_bytes(body)
    summary = client_mod._verify_export_file(str(dest), "json", 3)
    assert summary == {"path": str(dest), "format": "json", "rows": 3, "complete": True}
    # Numeric/null/formula semantics survive: bytes untouched, values parse.
    assert dest.read_bytes() == body
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["rows"][0] == {"n": 5, "z": None, "formula": "'=1+1"}
    assert parsed["rows"][1]["z"] is None


@pytest.mark.parametrize(
    ("ext", "body", "expected"),
    [
        (
            "json",
            b'{"metadata": {"schema_version": "export/1", "row_count": 2}, "rows": [{"n": 1}]',
            2,
        ),  # truncated
        (
            "json",
            b'{"metadata": {"schema_version": "export/1", "row_count": 2}, "rows": [',
            2,
        ),  # malformed
        (
            "json",
            json.dumps(
                {
                    "metadata": {"schema_version": "export/1", "row_count": 2},
                    "rows": [{"n": 1}],
                    "complete": False,
                }
            ).encode(),
            1,
        ),  # incomplete marker
        (
            "json",
            json.dumps(
                {
                    "metadata": {"schema_version": "export/1", "row_count": 9},
                    "rows": [{"n": 1}],
                    "complete": True,
                }
            ).encode(),
            1,
        ),  # metadata mismatch
        (
            "json",
            json.dumps(
                {
                    "metadata": {"schema_version": "export/1", "row_count": 2},
                    "rows": [{"n": 1}],
                    "complete": True,
                }
            ).encode(),
            1,
        ),  # row-count mismatch
        ("csv", b"path\n/a\n", 2),  # short
        ("csv", b"", 1),  # missing header
        ("csv", b"path\n" + b"x" * (client_mod.VERIFY_MAX_RECORD_BYTES + 1) + b"\n", 1),
    ],
)
def test_verify_rejects_bad_bodies(tmp_path, ext, body, expected):
    dest = tmp_path / f"bad.{ext}"
    dest.write_bytes(body)
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(str(dest), ext, expected)
    assert not dest.exists()


def test_download_refuses_existing_and_symlink_targets(tmp_path):
    sentinel = tmp_path / "sentinel.csv"
    sentinel.write_text("keep me\n", encoding="utf-8")
    body = b"path\n/a\n"
    opener = _FakeOpener(_FakeResponse(body, _export_headers(1)))
    with pytest.raises(SystemExit):
        client_mod.download_export(
            "http://127.0.0.1:9",
            "SYNTHETIC_TOKEN",
            {"site_id": "default"},
            "export-csv",
            str(sentinel),
            opener=opener,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep me\n"
    assert opener.requests == [], "refused before any request"

    link = tmp_path / "link.csv"
    try:
        link.symlink_to(sentinel)
    except OSError:
        pytest.skip("symlinks unavailable")
    opener2 = _FakeOpener(_FakeResponse(body, _export_headers(1)))
    with pytest.raises(SystemExit):
        client_mod.download_export(
            "http://127.0.0.1:9",
            "SYNTHETIC_TOKEN",
            {"site_id": "default"},
            "export-csv",
            str(link),
            opener=opener2,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep me\n"
    assert link.is_symlink()


def test_download_creates_owned_0600_and_cleans_midstream_failure(tmp_path):
    dest = tmp_path / "fresh.json"
    envelope = {
        "metadata": {"schema_version": "export/1", "row_count": 1},
        "rows": [{"n": 1}],
        "complete": True,
    }
    opener = _FakeOpener(_FakeResponse(json.dumps(envelope).encode(), _export_headers(1)))
    summary = client_mod.download_export(
        "http://127.0.0.1:9",
        "SYNTHETIC_TOKEN",
        {"site_id": "default"},
        "export-json",
        str(dest),
        opener=opener,
    )
    assert summary["complete"] is True and summary["rows"] == 1
    mode = stat.S_IMODE(os.stat(dest).st_mode)
    assert mode == 0o600
    assert opener.requests[0].get_header("Authorization") == "Bearer SYNTHETIC_TOKEN"

    class _FailingResponse(_FakeResponse):
        def read(self, size: int = -1) -> bytes:
            assert size is not None and size >= 0
            raise http.client.IncompleteRead(partial=b"cut", expected=64)

    victim = tmp_path / "victim.json"
    neighbour = tmp_path / "neighbour.json"
    neighbour.write_text("untouched\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        client_mod.download_export(
            "http://127.0.0.1:9",
            "SYNTHETIC_TOKEN",
            {"site_id": "default"},
            "export-json",
            str(victim),
            opener=_FakeOpener(_FailingResponse(b"", _export_headers(1))),
        )
    assert not victim.exists(), "run-owned partial must be removed"
    assert neighbour.read_text(encoding="utf-8") == "untouched\n"


def test_redirect_handler_matrix():
    handler = client_mod._SafeRedirectHandler()
    base = urllib.request.Request(
        "http://example.com/a", headers={"Authorization": "Bearer SYNTHETIC"}
    )
    same = handler.redirect_request(base, None, 302, "Found", {}, "http://example.com/b")
    assert same is not None
    assert same.get_header("Authorization") == "Bearer SYNTHETIC"
    upgrade = handler.redirect_request(base, None, 302, "Found", {}, "https://example.com/b")
    assert upgrade is not None
    assert upgrade.get_header("Authorization") == "Bearer SYNTHETIC"
    for target in (
        "http://evil.example/x",
        "http://example.com:9090/b",
    ):
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(base, None, 302, "Found", {}, target)
    https_base = urllib.request.Request(
        "https://example.com/a", headers={"Authorization": "Bearer SYNTHETIC"}
    )
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(https_base, None, 302, "Found", {}, "http://example.com/b")


def test_fetch_and_download_use_safe_opener(tmp_path):
    body = json.dumps({"summary": True}).encode()
    # json.load reads the small typed document whole: strict chunk
    # refusal applies to the export streaming path, not here.
    response = _FakeResponse(body, {}, strict=False)
    opener = _FakeOpener(response)
    out = client_mod.fetch(
        "http://127.0.0.1:9", "SYNTHETIC_TOKEN", "summary", {"site_id": "x"}, opener=opener
    )
    assert out == {"summary": True}
    assert opener.requests[0].get_header("Authorization") == "Bearer SYNTHETIC_TOKEN"

    envelope = {
        "metadata": {"schema_version": "export/1", "row_count": 1},
        "rows": [{"n": 1}],
        "complete": True,
    }
    dest = tmp_path / "dl.json"
    opener2 = _FakeOpener(_FakeResponse(json.dumps(envelope).encode(), _export_headers(1)))
    summary = client_mod.download_export(
        "http://127.0.0.1:9",
        "SYNTHETIC_TOKEN",
        {"site_id": "default"},
        "export-json",
        str(dest),
        opener=opener2,
    )
    assert summary["rows"] == 1


# ---------------------------------------------------------------------------
# 4. Projection honesty and bounds
# ---------------------------------------------------------------------------


def test_slow_endpoint_evidence_carries_server_ranking(measured_store):
    db, rules = measured_store
    conn = connect(db, read_only=True)
    try:
        envelope = tools.execute_tool(
            conn,
            rules,
            name="get_report",
            arguments=_args(report="slow_endpoints"),
            tool_call_id="tc1",
            observation_time=NOW,
        )
        result = envelope["result"]
        assert result["sort"] == "avg_desc"
        minimized = egress_mod.serialize_evidence("get_report", result)
        summary = egress_mod.project_evidence_summary(
            tool_name="get_report",
            tool_call_id="tc1",
            minimized=minimized,
            filters=envelope["filters"],
            observation_time=envelope["observation_time"],
            coverage=envelope["coverage"],
            full_result=result,
        )
        # The server ranking travels explicitly: no average-ranked
        # sample can be mistaken for a global p95 ranking.
        assert '"sort":"avg_desc"' in summary
        assert "sort_definition" in summary
        assert len(summary) <= egress_mod.EVIDENCE_PROJECTION_MAX_CHARS
    finally:
        conn.close()


def test_comparison_evidence_carries_both_windows_and_definition(store):
    db, rules = store
    conn = connect(db, read_only=True)
    try:
        envelope = tools.execute_tool(
            conn,
            rules,
            name="get_report",
            arguments=_args(report="comparison"),
            tool_call_id="tc1",
            observation_time=NOW,
        )
        result = envelope["result"]
        minimized = egress_mod.serialize_evidence("get_report", result)
        assert "trusted-window halves" in minimized["definition"]
        assert "never outside" in minimized["definition"]
        assert minimized["parent_window"]["time_from"] == FROM.isoformat()
        summary = egress_mod.project_evidence_summary(
            tool_name="get_report",
            tool_call_id="tc1",
            minimized=minimized,
            filters=envelope["filters"],
            observation_time=envelope["observation_time"],
            coverage=envelope["coverage"],
            full_result=result,
        )
        assert FROM.isoformat() in summary
        assert MID.isoformat() in summary
        assert TO.isoformat() in summary
        assert "definition" in summary
        assert len(summary) <= egress_mod.EVIDENCE_PROJECTION_MAX_CHARS
    finally:
        conn.close()

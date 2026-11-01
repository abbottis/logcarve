"""Strict bounded export-client validation, redirect and snapshot regressions.

Offline ONLY (synthetic stores, fake transports, blocked sockets).
Each test reproduces one independently confirmed gap FIRST (all were
observed ACCEPTED/returned-success on frozen ``7c0aee2``), then locks
the corrected strict behavior:

- JSON: the exact ``export/1`` envelope is mandatory (``metadata``
  object with compatible ``schema_version`` and a non-bool integer
  ``row_count`` matching the header count, ``rows`` array of objects
  of matching length, ``complete`` exactly ``true``) with strict
  grammar (no trailing commas, duplicate keys, non-finite constants
  or trailing junk); legitimate whitespace/UTF-8/escapes/chunk
  splits/large counts stay accepted, all bounded.
- CSV: valid nonempty unique header, exact width on EVERY row,
  strict quoting, oversized records rejected BEFORE the ``csv``
  reader can preallocate them via a bounded ``readline()`` record
  iterator (handle iteration and unbounded reads refused); quoted
  multiline fields stay one record. Same-count final-cell shortening
  is documented as undetectable (see the client docstring); row
  drops, grammar breaks and network aborts are caught.
- Redirects: non-http(s) schemes, credential-bearing userinfo,
  malformed ports, host/port changes and downgrades are refused
  before forwarding; only the canonical same-host http->https
  default-port upgrade is kept. Both ``fetch`` and
  ``download_export`` provably build the safe opener.
- Snapshot: an owned COMMIT failure rolls back and raises
  ``store_unavailable`` instead of returning success; caller-owned
  transactions stay untouched.
- CLI: the historical default fetches only the three standalone
  documents; comparison needs explicit validated baseline flags;
  report selectors page explicitly. Fake transports only.

Never a claim about full parity, release, native Linux or real-model
behavior.
"""

import io
import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import clients.logcarve_api_client as client_mod

REAL_META = {"schema_version": "export/1", "row_count": 1}


def _write(tmp_path, name, data: bytes) -> str:
    dest = tmp_path / name
    dest.write_bytes(data)
    return str(dest)


def _envelope(*, meta=None, rows=None, complete=True, extra=None):
    body = {}
    if meta is not None:
        body["metadata"] = meta
    if rows is not None:
        body["rows"] = rows
    if complete is not None:
        body["complete"] = complete
    if extra:
        body.update(extra)
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _rejects(tmp_path, ext, body: bytes, expected: int) -> None:
    dest = _write(tmp_path, f"bad.{ext}", body)
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(dest, ext, expected)
    assert not Path(dest).exists(), "partial file must be removed"


# ---------------------------------------------------------------------------
# JSON: mandatory envelope components
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        _envelope(rows=[{"a": 1}], complete=True),  # missing metadata
        _envelope(meta=dict(REAL_META), complete=True),  # missing rows
        _envelope(meta={"schema_version": "export/1"}, rows=[{"a": 1}], complete=True),
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete=None),  # no complete
        b"{}",
        b'{"metadata": {"schema_version": "export/1", "row_count": 1}}',
    ],
)
def test_json_missing_envelope_component_rejected(tmp_path, body):
    _rejects(tmp_path, "json", body, 1)


@pytest.mark.parametrize(
    "body",
    [
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": 1}], "complete": true,}'
        ),  # trailing envelope comma
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": 1},], "complete": true}'
        ),  # trailing rows comma
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [], "complete": true,}'
        ),  # trailing comma, empty rows
    ],
)
def test_json_trailing_commas_rejected(tmp_path, body):
    _rejects(tmp_path, "json", body, 1)


@pytest.mark.parametrize("scalar", [b"42", b'"s"', b"null", b"[1]", b"true"])
def test_json_scalar_rows_rejected(tmp_path, scalar):
    body = (
        b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
        b' "rows": [' + scalar + b'], "complete": true}'
    )
    _rejects(tmp_path, "json", body, 1)


@pytest.mark.parametrize(
    "body",
    [
        # Duplicate key inside a row.
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": 1, "a": 2}], "complete": true}'
        ),
        # Duplicate key inside metadata.
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1, "row_count": 1},'
            b' "rows": [{"a": 1}], "complete": true}'
        ),
        # Duplicate top-level key.
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": 1}], "complete": true, "complete": true}'
        ),
        # Duplicate key nested two levels deep.
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": {"b": 1, "b": 2}}], "complete": true}'
        ),
    ],
)
def test_json_duplicate_keys_rejected_at_any_depth(tmp_path, body):
    _rejects(tmp_path, "json", body, 1)


@pytest.mark.parametrize(
    "body",
    [
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": NaN}], "complete": true}'
        ),
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": Infinity}], "complete": true}'
        ),
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": [{"a": -Infinity}], "complete": true}'
        ),
    ],
)
def test_json_nonfinite_constants_rejected(tmp_path, body):
    _rejects(tmp_path, "json", body, 1)


@pytest.mark.parametrize(
    "body",
    [
        # Unknown top-level component.
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete=True, extra={"debug": 1}),
        # Missing schema_version.
        _envelope(meta={"row_count": 1}, rows=[{"a": 1}], complete=True),
        # Wrong schema_version.
        _envelope(
            meta={"schema_version": "export/2", "row_count": 1},
            rows=[{"a": 1}],
            complete=True,
        ),
        # Bool row_count.
        _envelope(
            meta={"schema_version": "export/1", "row_count": True},
            rows=[{"a": 1}],
            complete=True,
        ),
        # Float / string row_count.
        _envelope(
            meta={"schema_version": "export/1", "row_count": 1.0},
            rows=[{"a": 1}],
            complete=True,
        ),
        _envelope(
            meta={"schema_version": "export/1", "row_count": "1"},
            rows=[{"a": 1}],
            complete=True,
        ),
        # Out-of-range row_count.
        _envelope(
            meta={"schema_version": "export/1", "row_count": -1},
            rows=[{"a": 1}],
            complete=True,
        ),
        _envelope(
            meta={"schema_version": "export/1", "row_count": 250001},
            rows=[{"a": 1}],
            complete=True,
        ),
        # Metadata not an object; rows not an array.
        _envelope(meta=[1], rows=[{"a": 1}], complete=True),
        _envelope(meta=dict(REAL_META), rows={"a": 1}, complete=True),
        (
            b'{"metadata": {"schema_version": "export/1", "row_count": 1},'
            b' "rows": "nope", "complete": true}'
        ),
        # Complete not exactly true.
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete=1),
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete="true"),
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete=False),
        # Trailing junk after the envelope.
        _envelope(meta=dict(REAL_META), rows=[{"a": 1}], complete=True) + b"\n{}",
    ],
)
def test_json_bad_metadata_marker_shape_rejected(tmp_path, body):
    _rejects(tmp_path, "json", body, 1)


def _realistic_envelope(n_rows):
    rows = [
        {
            "path": f"/p{i}",
            "status": 200 if i % 7 else 500,
            "bytes": i,
            "note": None,
            "formula": "'=1+1",
            "text": 'Ünïcodé ✓ "quoted"\nnewline',
        }
        for i in range(n_rows)
    ]
    return json.dumps(
        {
            "metadata": {"schema_version": "export/1", "row_count": n_rows},
            "rows": rows,
            "complete": True,
        },
        ensure_ascii=False,
    ).encode("utf-8")


def test_json_accepts_whitespace_order_escapes_unicode(tmp_path, monkeypatch):
    # Shuffled keys, odd whitespace, escapes and multibyte text stay
    # valid; tiny chunks force splits inside escapes and multibyte.
    monkeypatch.setattr(client_mod, "VERIFY_CHUNK_BYTES", 7)
    raw = (
        b' {\n\t"complete" : true ,\r\n "rows" : [ {"t" : "a\\"b\\n\\u2713"} ] , '
        b'"metadata" : { "row_count" : 1 , "schema_version" : "export/1" } } \n'
    )
    dest = _write(tmp_path, "ok.json", raw)
    summary = client_mod._verify_export_file(dest, "json", 1)
    assert summary == {"path": dest, "format": "json", "rows": 1, "complete": True}


def test_json_accepts_empty_and_large_streamed(tmp_path, monkeypatch):
    empty = _write(
        tmp_path,
        "empty.json",
        json.dumps(
            {
                "metadata": {"schema_version": "export/1", "row_count": 0},
                "rows": [],
                "complete": True,
            }
        ).encode(),
    )
    assert client_mod._verify_export_file(empty, "json", 0)["rows"] == 0
    # Large row counts stream row-by-row: only the count is kept.
    monkeypatch.setattr(client_mod, "VERIFY_CHUNK_BYTES", 13)
    body = _realistic_envelope(3000)
    dest = _write(tmp_path, "big.json", body)
    summary = client_mod._verify_export_file(dest, "json", 3000)
    assert summary == {"path": dest, "format": "json", "rows": 3000, "complete": True}
    assert Path(dest).read_bytes() == body
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["rows"][0]["note"] is None
    assert parsed["rows"][0]["formula"] == "'=1+1"


# ---------------------------------------------------------------------------
# CSV: exact width, valid header, strict quoting, pre-reader bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"path,status,bytes\n/x,200\n", 1),  # short row
        (b"path,status\n/x,200,extra\n", 1),  # long row
        (b'path,note\n/a,"never closed\n', 1),  # unclosed quote at EOF
        (b'path,note\n/a,"closed"\n/b,"never closed\n', 2),  # unclosed later row
        (b"path,path\n/a,/b\n", 1),  # duplicate header
        (b"path,\n/a,/b\n", 1),  # empty header cell
        (b" ,status\n/a,200\n", 1),  # blank header cell
        (b"", 1),  # missing header
        (b"\n", 1),  # blank header line
        (b"path\n", 1),  # header only, row missing
        (b'path\n"a"b\n', 1),  # malformed quoting
        (b"path,status\n/a\n", 1),  # short single-column row
        (b"path\n/a\n/b\n", 1),  # extra row past the header count
    ],
)
def test_csv_malformed_rejected(tmp_path, body, expected):
    _rejects(tmp_path, "csv", body, expected)


def test_csv_accepts_quoted_multiline_unicode_and_escapes(tmp_path, monkeypatch):
    # Tiny readline slices split physical lines, escapes and
    # multibyte text mid-record; one logical record stays one row.
    monkeypatch.setattr(client_mod, "_CSV_READLINE_CHARS", 5)
    dest = tmp_path / "ok.csv"
    dest.write_text(
        'path,note,n\n"/a","line1\nline2 ✓ ""quoted""",5\n/b,plain,0\n',
        encoding="utf-8",
    )
    summary = client_mod._verify_export_file(str(dest), "csv", 2)
    assert summary == {"path": str(dest), "format": "csv", "rows": 2, "complete": True}


def test_csv_accepts_empty_export(tmp_path):
    dest = tmp_path / "empty.csv"
    dest.write_text("ts_utc,path\n", encoding="utf-8")
    assert client_mod._verify_export_file(str(dest), "csv", 0)["rows"] == 0


class _CountingHandle:
    """Wrap a text handle: bounded readline only, counts consumed bytes."""

    def __init__(self, raw):
        self._raw = raw
        self.consumed = 0
        self.calls = 0

    def readline(self, size=-1):
        assert size is not None and size >= 0, "unbounded readline() is forbidden"
        assert size <= client_mod._CSV_READLINE_CHARS, "oversized readline() bound"
        chunk = self._raw.readline(size)
        self.consumed += len(chunk.encode("utf-8"))
        self.calls += 1
        return chunk

    def read(self, size=-1):
        raise AssertionError("read() must not be used on the CSV path")

    def __iter__(self):
        raise AssertionError("bare handle iteration is forbidden")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._raw.__exit__(*exc)

    def close(self):
        return self._raw.close()


def _verify_csv_counted(monkeypatch, path, expected):
    import builtins

    real_open = builtins.open
    holders = {}

    def counting_open(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if str(file) == str(path) and "r" in mode:
            wrapped = _CountingHandle(handle)
            holders["h"] = wrapped
            return wrapped
        return handle

    monkeypatch.setattr(builtins, "open", counting_open)
    with pytest.raises(SystemExit):
        client_mod._verify_export_file(str(path), "csv", expected)
    assert not path.exists(), "partial file must be removed"
    return holders["h"]


def test_csv_very_long_many_columns_fails_early_bounded(tmp_path, monkeypatch):
    # One 3 MiB single-line record with thousands of columns: the
    # record iterator must fail oversized after ~1 MiB + one slice,
    # never consuming the whole file or handing it to csv.reader.
    path = tmp_path / "wide.csv"
    path.write_bytes(b"h\n" + b"x," * (3 * 1024 * 1024) + b"\n")
    size = path.stat().st_size
    assert size > 3 * 1024 * 1024
    guard = _verify_csv_counted(monkeypatch, path, 1)
    # Oversize trips on the first slice past 1 MiB: consumption stays
    # within the record bound plus readline granularity (the 2-byte
    # header record is already consumed before the hostile record).
    assert guard.consumed <= (
        client_mod.VERIFY_MAX_RECORD_BYTES + 2 * client_mod._CSV_READLINE_CHARS
    )
    assert guard.consumed < size // 2


def test_csv_quoted_multiline_oversized_fails_early_bounded(tmp_path, monkeypatch):
    # A quoted multiline record growing past 1 MiB across thousands
    # of physical lines must fail before csv.reader preallocates it.
    path = tmp_path / "tall.csv"
    with path.open("w", encoding="utf-8") as handle:
        handle.write('h,n\n"start\n')
        for _ in range(60000):
            handle.write("padding-line-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
    size = path.stat().st_size
    assert size > client_mod.VERIFY_MAX_RECORD_BYTES
    guard = _verify_csv_counted(monkeypatch, path, 1)
    assert guard.consumed <= (
        client_mod.VERIFY_MAX_RECORD_BYTES + 2 * client_mod._CSV_READLINE_CHARS
    )
    assert guard.consumed < size // 2


# ---------------------------------------------------------------------------
# Redirects: schemes, userinfo, ports, downgrade
# ---------------------------------------------------------------------------


def _redirect(base, target):
    handler = client_mod._SafeRedirectHandler()
    request = urllib.request.Request(base, headers={"Authorization": "Bearer SYNTHETIC"})
    return handler.redirect_request(request, None, 302, "Found", {}, target)


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.invalid:80/target",  # non-http scheme, same host+port
        "ftp://example.invalid/target",
        "file:///etc/hostname",
        "javascript:alert(1)",
        "http://user@example.invalid/target",  # credential-bearing userinfo
        "http://user:pass@example.invalid/target",
        "https://user@example.invalid/target",
        "http://example.invalid:evil/target",  # malformed port
        "http://other.invalid/target",  # cross-host
        "http://example.invalid:9090/target",  # port change
        "https://example.invalid:8443/target",  # off-default upgrade port
        "http://example.invalid./target",  # host spelling change
    ],
)
def test_redirect_unsafe_targets_refused_without_forwarding(target):
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _redirect("http://example.invalid/source", target)
    assert "SYNTHETIC" not in str(exc_info.value)


def test_redirect_https_downgrade_refused():
    with pytest.raises(urllib.error.HTTPError):
        _redirect("https://example.invalid/a", "http://example.invalid/b")


def test_redirect_safe_same_origin_and_canonical_upgrade_kept():
    same = _redirect("http://example.invalid/a", "http://example.invalid/b")
    assert same.get_header("Authorization") == "Bearer SYNTHETIC"
    upgrade = _redirect("http://example.invalid/a", "https://example.invalid/b")
    assert upgrade is not None
    assert upgrade.get_header("Authorization") == "Bearer SYNTHETIC"
    # Explicit default ports spell the same origin.
    explicit = _redirect("http://example.invalid:80/a", "https://example.invalid:443/b")
    assert explicit.get_header("Authorization") == "Bearer SYNTHETIC"
    tls_same = _redirect("https://example.invalid/a", "https://example.invalid/b")
    assert tls_same.get_header("Authorization") == "Bearer SYNTHETIC"


def test_fetch_and_download_build_safe_opener_by_default(tmp_path, monkeypatch):
    # The shipped opener carries the safe redirect handler.
    opener = client_mod._build_opener()
    assert any(isinstance(item, client_mod._SafeRedirectHandler) for item in opener.handlers)
    # And BOTH network paths construct it when no opener is passed
    # (fake transports only: the spy delegates to a canned opener).
    built = []

    class _Canned:
        def __init__(self, payload, headers):
            self._payload = io.BytesIO(payload)
            self.headers = headers

        def read(self, size=-1):
            return self._payload.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _CannedOpener:
        def __init__(self, canned):
            self.canned = canned
            self.requests = []

        def open(self, request, timeout=None):
            self.requests.append(request)
            return self.canned

    real_build = client_mod._build_opener

    def spy():
        built.append(True)
        real = real_build()
        assert any(isinstance(item, client_mod._SafeRedirectHandler) for item in real.handlers)
        return _CannedOpener(_Canned(b'{"ok": true}', {}))

    monkeypatch.setattr(client_mod, "_build_opener", spy)
    out = client_mod.fetch("http://127.0.0.1:9", "SYNTHETIC", "summary", {"site_id": "x"})
    assert out == {"ok": True} and built

    envelope = {
        "metadata": {"schema_version": "export/1", "row_count": 1},
        "rows": [{"n": 1}],
        "complete": True,
    }
    canned = _Canned(
        json.dumps(envelope).encode(),
        {"X-Logcarve-Export-Schema": "export/1", "X-Logcarve-Export-Rows": "1"},
    )
    holder = {"canned": canned}

    def spy2():
        built.append(True)
        return _CannedOpener(holder["canned"])

    monkeypatch.setattr(client_mod, "_build_opener", spy2)
    dest = tmp_path / "dl.json"
    summary = client_mod.download_export(
        "http://127.0.0.1:9", "SYNTHETIC", {"site_id": "x"}, "export-json", str(dest)
    )
    assert summary["rows"] == 1 and len(built) == 2


# ---------------------------------------------------------------------------
# Snapshot: owned COMMIT failure never returns success
# ---------------------------------------------------------------------------


class _FailCommit(sqlite3.Connection):
    """Connection double: every owned COMMIT raises; ROLLBACK works."""

    def execute(self, sql, *args, **kwargs):
        if isinstance(sql, str) and sql.strip().upper() == "COMMIT":
            raise sqlite3.OperationalError("injected COMMIT failure")
        return super().execute(sql, *args, **kwargs)


@pytest.fixture
def sized_store(tmp_path):
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b'198.51.100.7 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 "-" "P/1.0"\n'
    )
    db = tmp_path / "commit.sqlite3"
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
        hmac_key=b"commit-test-key",
    )
    return db


def _tool_args(**over):
    args = {
        "site_id": "default",
        "time_from": "2026-10-27T00:00:00+00:00",
        "time_to": "2026-10-28T00:00:00+00:00",
    }
    args.update(over)
    return args


def test_owned_commit_failure_raises_and_rolls_back(sized_store):
    from app.ai.tools import definitions as tools

    conn = sqlite3.connect(str(sized_store), factory=_FailCommit)
    try:
        with pytest.raises(tools.ToolError) as exc_info:
            tools.execute_tool(
                conn,
                None,
                name="get_summary",
                arguments=_tool_args(),
                tool_call_id="commit-probe",
            )
        assert exc_info.value.code == "store_unavailable"
        assert conn.in_transaction is False, "owned transaction must not stay active"
    finally:
        conn.close()


def test_caller_owned_transaction_survives_commit_failure(sized_store):
    from app.ai.tools import definitions as tools

    conn = sqlite3.connect(str(sized_store), factory=_FailCommit)
    try:
        conn.execute("BEGIN")
        envelope = tools.execute_tool(
            conn,
            None,
            name="get_summary",
            arguments=_tool_args(),
            tool_call_id="caller-owned-probe",
        )
        assert envelope["tool"] == "get_summary"
        assert conn.in_transaction is True, "caller-owned transaction stays intact"
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()


# ---------------------------------------------------------------------------
# CLI: historical default, explicit baseline, selectors (fake transports)
# ---------------------------------------------------------------------------

_CLI_BASE = [
    "--base-url",
    "http://127.0.0.1:9",
    "--site",
    "default",
    "--from",
    "2026-10-27T00:00:00+00:00",
    "--to",
    "2026-10-28T00:00:00+00:00",
    "--token",
    "SYNTHETIC",
]


def _stub_fetch(monkeypatch):
    calls = []

    def fake_fetch(base_url, token, endpoint, params, **kwargs):
        calls.append((endpoint, dict(params)))
        return {"endpoint": endpoint}

    monkeypatch.setattr(client_mod, "fetch", fake_fetch)
    return calls


def test_cli_default_fetches_only_baseline_endpoints(monkeypatch, capsys):
    calls = _stub_fetch(monkeypatch)
    assert client_mod.main(list(_CLI_BASE)) == 0
    assert [name for name, _ in calls] == ["summary", "crawlers", "findings"]
    documents = json.loads(capsys.readouterr().out)
    assert set(documents) == {"summary", "crawlers", "findings"}


def test_cli_comparison_without_baseline_fails_locally(monkeypatch):
    calls = _stub_fetch(monkeypatch)
    with pytest.raises(SystemExit) as exc_info:
        client_mod.main([*_CLI_BASE, "--endpoint", "comparison"])
    assert exc_info.value.code == 2
    assert calls == [], "no unauthorized derived baseline may run"


def test_cli_comparison_forwards_explicit_baseline(monkeypatch, capsys):
    calls = _stub_fetch(monkeypatch)
    argv = [
        *_CLI_BASE,
        "--endpoint",
        "comparison",
        "--baseline-from",
        "2026-10-26T00:00:00+00:00",
        "--baseline-to",
        "2026-10-27T00:00:00+00:00",
    ]
    assert client_mod.main(argv) == 0
    assert len(calls) == 1
    name, params = calls[0]
    assert name == "comparison"
    assert params["baseline_from"] == "2026-10-26T00:00:00+00:00"
    assert params["baseline_to"] == "2026-10-27T00:00:00+00:00"


@pytest.mark.parametrize(
    ("endpoint", "extra"),
    [
        ("comparison", ["--baseline-from", "2026-10-26T00:00:00+00:00"]),  # half pair
        ("comparison", ["--baseline-to", "2026-10-27T00:00:00+00:00"]),  # half pair
        (
            "comparison",
            ["--baseline-from", "not-a-date", "--baseline-to", "2026-10-27T00:00:00+00:00"],
        ),
        (
            "comparison",
            [  # naive datetimes carry no offset
                "--baseline-from",
                "2026-10-26T00:00:00",
                "--baseline-to",
                "2026-10-27T00:00:00",
            ],
        ),
        (
            "comparison",
            [  # inverted window
                "--baseline-from",
                "2026-10-27T00:00:00+00:00",
                "--baseline-to",
                "2026-10-26T00:00:00+00:00",
            ],
        ),
        (
            "summary",
            [  # baseline flags off-comparison
                "--baseline-from",
                "2026-10-26T00:00:00+00:00",
                "--baseline-to",
                "2026-10-27T00:00:00+00:00",
            ],
        ),
    ],
)
def test_cli_invalid_baseline_fails_locally(monkeypatch, endpoint, extra):
    calls = _stub_fetch(monkeypatch)
    with pytest.raises(SystemExit) as exc_info:
        client_mod.main([*_CLI_BASE, "--endpoint", endpoint, *extra])
    assert exc_info.value.code == 2
    assert calls == []


def test_cli_report_selectors_forwarded_and_validated(monkeypatch):
    calls = _stub_fetch(monkeypatch)
    argv = [
        *_CLI_BASE,
        "--endpoint",
        "slow-endpoints",
        "--source",
        "s1",
        "--limit",
        "5",
        "--offset",
        "10",
    ]
    assert client_mod.main(argv) == 0
    _, params = calls[0]
    assert params["source_id"] == "s1"
    assert params["limit"] == "5"
    assert params["offset"] == "10"
    for bad in (["--limit", "0"], ["--limit", "1001"], ["--offset", "-1"]):
        with pytest.raises(SystemExit) as exc_info:
            client_mod.main([*_CLI_BASE, "--endpoint", "slow-endpoints", *bad])
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# Real ExportStream bodies verify end to end (CSV + JSON)
# ---------------------------------------------------------------------------


def _compat_store(tmp_path):
    from app.analytics.rules import load_rules
    from app.db.importer import run_import
    from app.db.migrations_runner import migrate
    from app.ingestion.sources import SourceConfig

    root = tmp_path / "logs"
    root.mkdir()
    (root / "access.log").write_bytes(
        b'198.51.100.7 - - [27/Oct/2026:10:00:00 +0000] "GET /plain HTTP/1.1" 200 10 "-" "Probe/1.0"\n'
        b'198.51.100.8 - - [27/Oct/2026:10:01:00 +0000] "GET /=formula-path HTTP/1.1" 404 20 "-" "Probe/1.0"\n'
        b'198.51.100.9 - - [27/Oct/2026:10:02:00 +0000] "GET /unicode HTTP/1.1" 200 30 "-" "\xc3\x9cn\xc3\xafcod\xc3\xa9 \xe2\x9c\x93"\n'
    )
    db = tmp_path / "compat.sqlite3"
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
        hmac_key=b"compat-test-key",
    )
    try:
        rules = (
            load_rules(Path("config/bot_rules.yaml")).rules
            + load_rules(Path("config/security_rules.yaml")).rules
        )
    except OSError:
        rules = None
    return db, rules


def _export_body_to_file(db, rules, fmt, dest, filt):
    from app.api.routes_export import ExportStream, csv_chunks, json_chunks

    stream = ExportStream(db).open()
    metadata = stream.prepare(filt, rules, "oldest", max_rows=250_000, display_timezone="UTC")
    chunks = csv_chunks(stream.rows()) if fmt == "csv" else json_chunks(metadata, stream.rows())
    with open(dest, "w", encoding="utf-8", newline="") as handle:
        handle.writelines(chunks)
    assert stream.closed
    return metadata


def test_real_export_stream_bodies_verify_csv_and_json(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    monkeypatch.chdir(Path(__file__).resolve().parent.parent.parent)
    db, rules = _compat_store(tmp_path)
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 11, 0, tzinfo=UTC),
        ),
    )
    for fmt in ("csv", "json"):
        dest = tmp_path / f"real.{fmt}"
        metadata = _export_body_to_file(db, rules, fmt, dest, filt)
        assert metadata["row_count"] == 3
        summary = client_mod._verify_export_file(str(dest), fmt, 3)
        assert summary == {"path": str(dest), "format": fmt, "rows": 3, "complete": True}
    blob = (tmp_path / "real.json").read_text(encoding="utf-8")
    envelope = json.loads(blob)
    assert envelope["metadata"]["schema_version"] == "export/1"
    assert all(isinstance(row, dict) for row in envelope["rows"])
    # Null timing (combined logs carry no timing), unicode and raw
    # formula text survive the JSON round-trip untouched.
    assert envelope["rows"][0]["request_time_ms"] is None
    assert "Ünïcodé ✓" in envelope["rows"][2]["user_agent"]
    assert envelope["rows"][1]["path"] == "/=formula-path"
    # The client never rewrites: the hostile path arrives verbatim in
    # both bodies (server-side neutralization, if any, is preserved
    # byte-for-byte by verification).
    csv_blob = (tmp_path / "real.csv").read_text(encoding="utf-8")
    assert "/=formula-path" in csv_blob
    assert "198.51.100" not in blob + csv_blob


def test_real_export_stream_empty_window_verifies(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from app.analytics.contracts import AnalyticsFilter, TimeWindow

    monkeypatch.chdir(Path(__file__).resolve().parent.parent.parent)
    db, rules = _compat_store(tmp_path)
    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 12, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 13, 0, tzinfo=UTC),
        ),
    )
    for fmt in ("csv", "json"):
        dest = tmp_path / f"empty.{fmt}"
        metadata = _export_body_to_file(db, rules, fmt, dest, filt)
        assert metadata["row_count"] == 0
        assert client_mod._verify_export_file(str(dest), fmt, 0)["rows"] == 0

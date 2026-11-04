"""Parity T2a tests: T1b preflight regressions plus shared C/D analytics.

Covers the mandatory T1b review preflight (SecretStr-safe capture,
same-lock source binding, alias persistence for old sources), the
data-correctness probes (partial upstream timing, overflow-stable
statistics) and the T2a shared analytics slices:

C: measured latency (avg/median/P50/P95/P99, documented interpolation),
slow endpoints, cache distribution with HIT-ratio denominator, 304
separation, measured-vs-inferred MIME, version/TLS/host distributions,
new metadata filters with serialization round-trips.

D: bot 3xx/4xx/5xx by path+rule, AI-only paths with comparison
scope/caveat, external referrer-path 404s with internal/external split.

All fixtures are synthetic and generated in tmp dirs; the 120-row
fixture, the HMAC identity, the auth/model ledger and the 77-rule bot
catalog are never modified here. Synthetic data only.
"""

import dataclasses
import json
import math
import pickle
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import queries, service
from app.analytics.contracts import AnalyticsFilter, SlowEndpointsQuery, TimeWindow
from app.analytics.rules import load_rules
from app.db import repositories
from app.db.database import connect, writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.reprocess import run_reprocess
from app.ingestion.combined import (
    NGINX_COMBINED,
    NGINX_EXTENDED,
    CapturedOriginal,
    normalize_multi_seconds_to_ms,
    parse_line,
)
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
HMAC_KEY = b"parity-t2a-test-key"
SITE = "site-t2a"
SITE_HOST = "example.org"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 0, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 28, 0, 0, 0, tzinfo=UTC),
)

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
GPT_UA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1"
OAI_UA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0"
CURL_UA = "curl/8.5.0"


def test_bot_catalog_untouched():
    """The 77-rule versioned catalog this slice classifies against."""
    assert len(BOT_RULES) == 77


def _filt(**overrides) -> AnalyticsFilter:
    base = {"site_id": SITE, "window": WINDOW}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _expected_quantile(values: list[float], quantum: float) -> float:
    """Documented interpolation, reimplemented plainly for the test."""
    ordered = sorted(values)
    rank = quantum * (len(ordered) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if high == low:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


# --- T1b preflight: capture can no longer leak through asdict ---


def test_captured_original_survives_asdict_and_serialization():
    captured = CapturedOriginal("192.0.2.44")
    assert captured.reveal() == "192.0.2.44"
    with pytest.raises(TypeError):
        dataclasses.asdict(captured)

    @dataclasses.dataclass
    class Wrapper:
        cap: object

    nested = dataclasses.asdict(Wrapper(cap=captured))
    for value in nested.values():
        assert not (isinstance(value, str) and "192.0.2" in value)
    assert "192.0.2.44" not in repr(nested)
    assert b"192.0.2.44" not in pickle.dumps(captured)
    with pytest.raises(TypeError):
        json.dumps({"original": captured})
    for rendered in (repr(captured), str(captured), repr([captured])):
        assert "192.0.2.44" not in rendered


# --- T1b preflight: deterministic source-registration race ---


def _combined_line(index: int, path: str = "/race") -> bytes:
    return (
        f"203.0.113.20 - - [27/Oct/2026:10:00:{index:02d} +0000] "
        f'"GET {path} HTTP/1.1" 200 10 "-" "RaceAgent"\n'
    ).encode()


def test_source_binding_race_rejected_same_lock(tmp_path, monkeypatch):
    """Inject a foreign registration after the precheck: must roll back."""
    import app.db.importer as importer_mod

    root = tmp_path / "logs"
    root.mkdir()
    (root / "race.log").write_bytes(b"".join(_combined_line(i) for i in range(3)))
    db = tmp_path / "race.sqlite3"
    source = SourceConfig(
        source_id="race-source",
        format_id=NGINX_COMBINED,
        allowed_root=root,
        relative_path="race.log",
    )
    original_check = importer_mod._check_source_binding

    def _check_then_inject(db_path, *, source_id: str, site_id: str) -> None:
        original_check(db_path, source_id=source_id, site_id=site_id)
        with writer_transaction(db_path) as conn:
            repositories.ensure_site(
                conn,
                site_id="site-foreign",
                name="Foreign",
                hostname="foreign.example",
                created_at=NOW.isoformat(),
            )
            repositories.ensure_source(
                conn,
                source_id=source_id,
                site_id="site-foreign",
                server_type="nginx",
                format_id=NGINX_COMBINED,
                path_alias="race.log",
            )

    monkeypatch.setattr(importer_mod, "_check_source_binding", _check_then_inject)
    with pytest.raises(repositories.SourceBindingError) as excinfo:
        run_import(
            db,
            source=source,
            site_id="site-victim",
            site_name="Victim",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="race.log",
            hmac_key=HMAC_KEY,
        )
    assert excinfo.value.code == repositories.SOURCE_SITE_MISMATCH_CODE
    conn = connect(db, read_only=True)
    try:
        sites = [row[0] for row in conn.execute("SELECT id FROM sites").fetchall()]
        assert sites == ["site-foreign"]
        assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0] == 0
    finally:
        conn.close()


# --- T1b preflight: alias persistence for already-bound sources ---


def test_old_source_alias_update_preserves_core_and_reclassifies(tmp_path):
    """Pre-T1b rows (NULL aliases) gain aliases; core fields preserved."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "alias.log").write_bytes(
        b'203.0.113.20 - - [27/Oct/2026:10:00:01 +0000] "GET /gone HTTP/1.1"'
        b' 404 9 "https://shop.example/sale?utm=x" "AliasAgent"'
        b' example.org - - - - "-"\n'
        b'203.0.113.20 - - [27/Oct/2026:10:00:02 +0000] "GET /gone HTTP/1.1"'
        b' 404 9 "https://external.example/other" "AliasAgent"'
        b' example.org - - - - "-"\n'
    )
    db = tmp_path / "alias.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        repositories.ensure_site(
            conn,
            site_id=SITE,
            name="T2a",
            hostname=SITE_HOST,
            created_at=NOW.isoformat(),
        )
        # Legacy row predating the alias column: NULL stored aliases.
        repositories.ensure_source(
            conn,
            source_id="alias-source",
            site_id=SITE,
            server_type="nginx",
            format_id=NGINX_EXTENDED,
            path_alias="alias.log",
        )
    before = connect(db, read_only=True)
    try:
        core_before = before.execute(
            "SELECT site_id, server_type, format_id, path_alias, enabled FROM log_sources"
            " WHERE id = 'alias-source'"
        ).fetchone()
        assert (
            before.execute(
                "SELECT allowed_hosts FROM log_sources WHERE id = 'alias-source'"
            ).fetchone()[0]
            is None
        )
    finally:
        before.close()
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="alias-source",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="alias.log",
            allowed_hosts=[SITE_HOST, "shop.example"],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="alias.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 2
    check = connect(db, read_only=True)
    try:
        row = check.execute("SELECT * FROM log_sources WHERE id = 'alias-source'").fetchone()
        assert tuple(row[1:6]) == tuple(core_before)
        assert json.loads(row[6]) == [SITE_HOST, "shop.example"]
        stored_hosts = repositories.fetch_source_allowed_hosts(check, source_id="alias-source")
        assert stored_hosts == [SITE_HOST, "shop.example"]
    finally:
        check.close()
    filt = _filt(source_id="alias-source")
    conn = connect(db, read_only=True)
    try:
        report = service.referrer_404s(conn, filt, None)
    finally:
        conn.close()
    assert report["own_hosts"] == [SITE_HOST, "shop.example"]
    by_host = {item["referer_host"]: item for item in report["items"]}
    assert by_host["shop.example"]["internal"] is True
    assert by_host["external.example"]["internal"] is False
    assert report["total_groups"] == 2


def test_update_source_hosts_guarded_and_validated(tmp_path):
    db = tmp_path / "hosts.sqlite3"
    migrate(db)
    with writer_transaction(db) as conn:
        repositories.ensure_site(
            conn, site_id=SITE, name="T2a", hostname=SITE_HOST, created_at=NOW.isoformat()
        )
        repositories.ensure_source(
            conn,
            source_id="s1",
            site_id=SITE,
            server_type="nginx",
            format_id=NGINX_COMBINED,
            path_alias="a.log",
        )
        assert (
            repositories.update_source_hosts(
                conn, source_id="nope", site_id=SITE, allowed_hosts=["example.org"]
            )
            is False
        )
        # Guarded by site: a foreign-site row is never touched (False, no raise).
        assert (
            repositories.update_source_hosts(
                conn, source_id="s1", site_id="other-site", allowed_hosts=["example.org"]
            )
            is False
        )
        with pytest.raises(ValueError):
            repositories.update_source_hosts(
                conn, source_id="s1", site_id=SITE, allowed_hosts=["has space.example"]
            )
    check = connect(db, read_only=True)
    try:
        assert repositories.fetch_source_allowed_hosts(check, source_id="s1") is None
    finally:
        check.close()


# --- Data-correctness probe: partial upstream timing ---


def _extended_line(
    *,
    path: str = "/x",
    status: int = 200,
    size: str = "10",
    referer: str = "-",
    ua: str = "-",
    host: str = "example.org",
    cache: str = "-",
    request_time: str = "-",
    mime: str = "-",
    tls: str = "-",
    upstream: str = "-",
    version: str = " HTTP/1.1",
    ip: str = "203.0.113.20",
    minute: int = 0,
) -> bytes:
    return (
        f"{ip} - - [27/Oct/2026:10:{minute:02d}:00 +0000] "
        f'"GET {path}{version}" {status} {size} "{referer}" "{ua}" '
        f'{host} {cache} {request_time} {mime} {tls} "{upstream}"\n'
    ).encode()


def test_partial_upstream_helper_line_import_service_agree():
    """'0.100, -' keeps the event: total unavailable, request kept."""
    assert normalize_multi_seconds_to_ms("0.100, -") == (None, None)
    assert normalize_multi_seconds_to_ms("-") == (None, None)
    assert normalize_multi_seconds_to_ms("0.050, 0.070") == (120.0, 2)
    record = parse_line(
        _extended_line(request_time="0.042", upstream="0.100, -"),
        source_id="s",
        format_id=NGINX_EXTENDED,
        hmac_key=HMAC_KEY,
    )
    assert record.extra.request_time_ms == pytest.approx(42.0)
    assert record.extra.upstream_time_ms is None
    assert record.extra.upstream_count is None


def test_partial_upstream_import_and_reprocess_carry_same_meaning(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "partial.log").write_bytes(
        _extended_line(path="/a", request_time="0.042", upstream="0.100, -", minute=1)
        + _extended_line(path="/b", request_time="0.010", upstream="0.004, 0.006", minute=2)
    )
    db = tmp_path / "partial.sqlite3"
    source = SourceConfig(
        source_id="partial-source",
        format_id=NGINX_EXTENDED,
        allowed_root=root,
        relative_path="partial.log",
        allowed_hosts=[SITE_HOST],
    )
    imported = run_import(
        db,
        source=source,
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="partial.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 2
    conn = connect(db)
    try:
        rows = conn.execute(
            "SELECT path, request_time_ms, upstream_time_ms, upstream_count FROM requests"
            " ORDER BY path"
        ).fetchall()
        assert rows[0][1] == pytest.approx(42.0)
        assert rows[0][2] is None and rows[0][3] is None
        assert (rows[1][1], rows[1][2], rows[1][3]) == (10.0, 10.0, 2)
    finally:
        conn.close()
    repro = run_reprocess(
        db,
        source=source,
        site_id=SITE,
        site_hostname=SITE_HOST,
        server_type="nginx",
        hmac_key=HMAC_KEY,
    )
    assert repro.status == "completed" and repro.rows_verified == 2
    conn = connect(db, read_only=True)
    try:
        stats = queries.timing_stats(conn, _filt(), None, "upstream_time_ms")
        assert (stats["measured"], stats["missing"]) == (1, 1)
        overview = service.performance_overview(conn, _filt(), None)
        assert overview["upstream_ms"]["measured"] == 1
        assert overview["latency_ms"]["measured"] == 2
    finally:
        conn.close()


# --- Data-correctness probe: overflow-stable averages/quantiles ---


def test_huge_but_finite_timings_never_emit_inf_or_nan(tmp_path):
    """Two ~1e308 ms observations: AVG overflows honestly, JSON stays safe."""
    huge_seconds = "1" + "0" * 305
    assert math.isfinite(float(huge_seconds) * 1000.0)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "huge.log").write_bytes(
        _extended_line(path="/huge", request_time=huge_seconds, minute=1)
        + _extended_line(path="/huge", request_time=huge_seconds, minute=2)
    )
    db = tmp_path / "huge.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="huge-source",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="huge.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="huge.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 2
    conn = connect(db, read_only=True)
    try:
        overview = service.performance_overview(conn, _filt(), None)
        latency = overview["latency_ms"]
        assert latency["measured"] == 2 and latency["missing"] == 0
        assert latency["average_ms"] is None
        assert any("overflow" in str(w) for w in latency["warnings"])
        assert latency["p50_ms"] is not None and math.isfinite(latency["p50_ms"])
        assert latency["max_ms"] is not None and math.isfinite(latency["max_ms"])

        def _walk(value):
            if isinstance(value, float):
                assert math.isfinite(value), f"non-finite float in response: {value!r}"
            elif isinstance(value, dict):
                for item in value.values():
                    _walk(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _walk(item)

        _walk(overview)
        json.dumps(overview)
    finally:
        conn.close()


# --- T2a-C: hand-counted 24-row measured fixture ---


def _t2a_c_lines() -> bytes:
    rows = [
        # path, status, referer, ua, host, cache, req_s, mime, tls, upstream
        (
            "/home",
            200,
            "-",
            BROWSER_UA,
            "example.org",
            "HIT",
            "0.010",
            "text/html",
            "TLSv1.3",
            "0.005",
        ),
        (
            "/style.css",
            200,
            "-",
            BROWSER_UA,
            "example.org",
            "HIT",
            "0.000",
            "text/css",
            "TLSv1.3",
            "-",
        ),
        (
            "/app.js",
            200,
            "-",
            BROWSER_UA,
            "example.org",
            "MISS",
            "0.120",
            "application/javascript",
            "TLSv1.2",
            "0.050, 0.070",
        ),
        (
            "/img.png",
            200,
            "-",
            GOOGLE_UA,
            "alias.example",
            "HIT",
            "0.030",
            "image/png",
            "TLSv1.3",
            "-",
        ),
        (
            "/img.png",
            200,
            "-",
            BROWSER_UA,
            "alias.example",
            "HIT",
            "0.030",
            "image/png",
            "TLSv1.3",
            "-",
        ),
        (
            "/ai-only-page",
            200,
            "-",
            GPT_UA,
            "example.org",
            "BYPASS",
            "0.200",
            "text/html",
            "TLSv1.3",
            "0.100, -",
        ),
        (
            "/ai-only-page",
            200,
            "-",
            OAI_UA,
            "example.org",
            "BYPASS",
            "0.250",
            "text/html",
            "TLSv1.3",
            "-",
        ),
        ("/shared-ai", 200, "-", GPT_UA, "-", "MISS", "0.080", "text/html", "-", "-"),
        ("/shared-ai", 200, "-", BROWSER_UA, "-", "MISS", "0.090", "text/html", "-", "-"),
        ("/old", 301, "-", GPT_UA, "example.org", "-", "-", "-", "-", "-"),
        ("/old", 301, "-", GOOGLE_UA, "example.org", "-", "0.015", "-", "-", "-"),
        (
            "/missing-thing",
            404,
            "https://external.example/blog/post?utm=x",
            GPT_UA,
            "example.org",
            "-",
            "0.005",
            "text/html",
            "TLSv1.2",
            "-",
        ),
        (
            "/missing-thing",
            404,
            "https://alias.example/internal/page?token=secret",
            BROWSER_UA,
            "example.org",
            "-",
            "0.006",
            "text/html",
            "TLSv1.2",
            "-",
        ),
        (
            "/secret-leak-probe",
            404,
            "https://user:pw@external.example:8443/x?pw=hunter2",
            CURL_UA,
            "example.org",
            "-",
            "0.007",
            "-",
            "-",
            "-",
        ),
        ("/gone", 410, "-", GPT_UA, "-", "-", "-", "-", "-", "-"),
        ("/login", 401, "-", BROWSER_UA, "example.org", "-", "0.050", "-", "TLSv1.3", "-"),
        (
            "/api/data",
            500,
            "-",
            GOOGLE_UA,
            "example.org",
            "-",
            "0.300",
            "application/json",
            "TLSv1.2",
            "0.200",
        ),
        (
            "/cached.css",
            304,
            "-",
            BROWSER_UA,
            "example.org",
            "-",
            "0.002",
            "text/css",
            "TLSv1.2",
            "-",
        ),
        (
            "/weird",
            200,
            "javascript:alert(1)",
            BROWSER_UA,
            "example.org",
            "HIT",
            "0.040",
            "text/html; charset=utf-8",
            "TLSv1.3",
            "-",
        ),
        ("/weird2", 200, "-", "-", "example.org", "MISS", "0.040", "text/html", "TLSv1.3", "-"),
        (
            "/slow-report",
            200,
            "-",
            BROWSER_UA,
            "example.org",
            "MISS",
            "1.500",
            "text/html",
            "TLSv1.3",
            "0.900, 0.400",
        ),
        (
            "/slow-report",
            200,
            "-",
            BROWSER_UA,
            "example.org",
            "MISS",
            "2.000",
            "text/html",
            "TLSv1.3",
            "-",
        ),
        ("/zero2", 200, "-", GPT_UA, "alias.example", "HIT", "0.000", "image/png", "-", "-"),
        ("/plain-absent", 200, "-", BROWSER_UA, "-", "-", "-", "-", "-", "-"),
    ]
    lines = []
    for index, (path, status, referer, ua, host, cache, req, mime, tls, upstream) in enumerate(
        rows
    ):
        lines.append(
            f"203.0.11.{(index % 50) + 1} - - [27/Oct/2026:10:{index:02d}:00 +0000] "
            f'"GET {path} HTTP/1.1" {status} 100 "{referer}" "{ua}" '
            f'{host} {cache} {req} {mime} {tls} "{upstream}"\n'
        )
    # One version edge: row 17 speaks HTTP/2, row 24 omits the version.
    lines[16] = lines[16].replace("HTTP/1.1", "HTTP/2")
    lines[23] = lines[23].replace("GET /plain-absent HTTP/1.1", "GET /plain-absent")
    return "".join(lines).encode()


MEASURED_MS = [
    10.0,
    0.0,
    120.0,
    30.0,
    30.0,
    200.0,
    250.0,
    80.0,
    90.0,
    15.0,
    5.0,
    6.0,
    7.0,
    50.0,
    300.0,
    2.0,
    40.0,
    40.0,
    1500.0,
    2000.0,
    0.0,
]


def _import_t2a_c(tmp_path, name: str = "t2a-c.log") -> Path:
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / name).write_bytes(_t2a_c_lines())
    db = tmp_path / "t2a-c.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="t2a-c-source",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path=name,
            allowed_hosts=[SITE_HOST, "alias.example"],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias=name,
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 24
    return db


def test_t2a_c_latency_exact_with_zero_and_missing(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        overview = service.performance_overview(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    latency = overview["latency_ms"]
    assert overview["units"] == "milliseconds"
    assert overview["latency_available"] is True
    assert (latency["measured"], latency["missing"], latency["total"]) == (21, 3, 24)
    assert latency["coverage"] == pytest.approx(21 / 24)
    assert latency["min_ms"] == pytest.approx(0.0)
    assert latency["max_ms"] == pytest.approx(2000.0)
    assert latency["average_ms"] == pytest.approx(sum(MEASURED_MS) / 21)
    assert latency["median_ms"] == pytest.approx(40.0)
    assert latency["p50_ms"] == pytest.approx(_expected_quantile(MEASURED_MS, 0.50))
    assert latency["p95_ms"] == pytest.approx(1500.0)
    assert latency["p99_ms"] == pytest.approx(1900.0)
    assert "linear interpolation" in overview["percentile_definition"]
    upstream = overview["upstream_ms"]
    assert (upstream["measured"], upstream["missing"]) == (4, 20)
    assert upstream["average_ms"] == pytest.approx((5.0 + 120.0 + 200.0 + 1300.0) / 4)
    assert upstream["p50_ms"] == pytest.approx(160.0)
    assert latency["warnings"] == [] and upstream["warnings"] == []


def test_t2a_c_cache_hit_ratio_and_304_separation(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        overview = service.performance_overview(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    cache = overview["cache"]
    by_value = {item["value"]: item["requests"] for item in cache["items"]}
    assert by_value == {"HIT": 6, "MISS": 6, "BYPASS": 2, "Unknown": 10}
    assert cache["total"] == 24
    assert (cache["cache_measured"], cache["cache_missing"]) == (14, 10)
    assert cache["hit_requests"] == 6
    assert cache["hit_ratio"] == pytest.approx(6 / 14)
    assert "absent excluded" in cache["hit_ratio_denominator"]
    assert cache["not_modified_304"] == 1
    assert "not crawl waste" in cache["not_modified_note"]


def test_t2a_c_mime_version_tls_host_distributions(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        overview = service.performance_overview(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    mime_block = overview["mime_vs_resource"]
    assert mime_block["total"] == 24 and mime_block["other_requests"] == 0
    assert mime_block["truncated"] is False
    mime = {(m["mime_type"], m["resource_kind"]): m["requests"] for m in mime_block["items"]}
    assert mime[("text/html", "page")] == 11
    # Measured-vs-inferred divergence: /zero2 logs image/png for an
    # extensionless path, so it lands on the page kind, not image.
    assert mime[("image/png", "image")] == 2
    assert mime[("image/png", "page")] == 1
    assert mime[("text/css", "style")] == 2
    assert mime[("application/javascript", "script")] == 1
    # /api/data logs application/json for an extensionless path: page kind.
    assert mime[("application/json", "page")] == 1
    assert sum(mime.values()) == 24
    versions = {i["value"]: i["requests"] for i in overview["http_versions"]["items"]}
    assert versions == {"HTTP/1.1": 22, "HTTP/2": 1, "Unknown": 1}
    tls = {i["value"]: i["requests"] for i in overview["tls_protocols"]["items"]}
    assert tls == {"TLSv1.3": 11, "TLSv1.2": 5, "Unknown": 8}
    hosts = {i["value"]: i["requests"] for i in overview["logged_hosts"]["items"]}
    assert hosts == {"example.org": 17, "alias.example": 3, "Unknown": 4}


def test_t2a_c_slow_endpoints_counts_percentiles_ties(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.slow_endpoints(conn, SlowEndpointsQuery(filt=_filt()), BOT_RULES)
    finally:
        conn.close()
    assert result["total_paths"] == 16
    order = [item["path"] for item in result["items"]]
    assert order[:6] == [
        "/slow-report",
        "/api/data",
        "/ai-only-page",
        "/app.js",
        "/shared-ai",
        "/login",
    ]
    tie40 = [item["path"] for item in result["items"] if item["average_ms"] == 40.0]
    assert tie40 == ["/weird", "/weird2"]
    slow = result["items"][0]
    assert slow["path"] == "/slow-report" and slow["measured"] == 2
    assert slow["average_ms"] == pytest.approx(1750.0)
    assert slow["p95_ms"] == pytest.approx(1975.0)
    ai = next(item for item in result["items"] if item["path"] == "/ai-only-page")
    assert ai["p95_ms"] == pytest.approx(247.5)
    fresh = connect(db, read_only=True)
    try:
        p95 = service.slow_endpoints(
            fresh,
            SlowEndpointsQuery(filt=_filt(limit=3), sort="p95_desc"),
            BOT_RULES,
        )
    finally:
        fresh.close()
    # Exact global ranking: no frequency-preselected candidate bound.
    assert p95["meta"] == {"candidate_paths": 16, "ranking": "p95_desc"}
    assert "p95_candidate_bound" not in p95["meta"]
    assert [i["path"] for i in p95["items"]] == ["/slow-report", "/api/data", "/ai-only-page"]


def test_t2a_c_metadata_filters_and_serialization(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        assert (
            service.performance_overview(conn, _filt(server_host="alias.example"), BOT_RULES)[
                "latency_ms"
            ]["total"]
            == 3
        )
        assert (
            service.performance_overview(conn, _filt(cache_status="hit"), BOT_RULES)["latency_ms"][
                "total"
            ]
            == 6
        )
        mime = service.performance_overview(
            conn, _filt(mime_type="Text/HTML; charset=x"), BOT_RULES
        )
        assert mime["latency_ms"]["total"] == 11
        assert (
            service.performance_overview(conn, _filt(tls_protocol="TLSv1.2"), BOT_RULES)[
                "latency_ms"
            ]["total"]
            == 5
        )
        assert (
            service.performance_overview(conn, _filt(http_version="HTTP/2"), BOT_RULES)[
                "latency_ms"
            ]["total"]
            == 1
        )
        assert (
            service.performance_overview(conn, _filt(timing_available=True), BOT_RULES)[
                "latency_ms"
            ]["total"]
            == 21
        )
        assert (
            service.performance_overview(conn, _filt(timing_available=False), BOT_RULES)[
                "latency_ms"
            ]["total"]
            == 3
        )
        assert (
            service.performance_overview(conn, _filt(upstream_available=True), BOT_RULES)[
                "upstream_ms"
            ]["measured"]
            == 4
        )
        ranged = service.performance_overview(
            conn, _filt(timing_min_ms=100.0, timing_max_ms=300.0), BOT_RULES
        )
        assert ranged["latency_ms"]["total"] == 4
        with pytest.raises(ValueError):
            _filt(cache_status="not a cache!!")
        with pytest.raises(ValueError):
            _filt(timing_min_ms=9.0, timing_max_ms=1.0)
    finally:
        conn.close()
    filt = _filt(server_host="alias.example", cache_status="HIT", timing_min_ms=1.0)
    clone = AnalyticsFilter.model_validate(filt.model_dump())
    assert clone == filt
    assert service._filter_dict(clone)["server_host"] == "alias.example"


def test_t2a_c_legacy_combined_honestly_unavailable(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    (root / "legacy.log").write_bytes(
        b'203.0.113.9 - - [27/Oct/2026:10:00:01 +0000] "GET /a HTTP/1.1" 200 10 "-" "A"\n'
        b'203.0.113.9 - - [27/Oct/2026:10:00:02 +0000] "GET /b HTTP/1.1" 200 10 "-" "A"\n'
    )
    db = tmp_path / "legacy.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="leg", format_id=NGINX_COMBINED, allowed_root=root, relative_path="legacy.log"
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="legacy.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.records_inserted == 2
    conn = connect(db, read_only=True)
    try:
        overview = service.performance_overview(conn, _filt(), BOT_RULES)
        assert overview["latency_available"] is False
        assert overview["latency_ms"]["measured"] == 0
        assert overview["latency_ms"]["missing"] == 2
        assert overview["latency_ms"]["average_ms"] is None
    finally:
        conn.close()


def test_t2a_c_paging_and_repeat_run_equality(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        first = service.performance_overview(conn, _filt(), BOT_RULES, observation_time=NOW)
        second = service.performance_overview(conn, _filt(), BOT_RULES, observation_time=NOW)
        assert first == second
        ai_first = service.ai_only_paths(conn, _filt(), BOT_RULES, observation_time=NOW)
        ai_second = service.ai_only_paths(conn, _filt(), BOT_RULES, observation_time=NOW)
        assert ai_first == ai_second
        page1 = service.slow_endpoints(
            conn, SlowEndpointsQuery(filt=_filt(limit=5, offset=0)), BOT_RULES
        )
        page2 = service.slow_endpoints(
            conn, SlowEndpointsQuery(filt=_filt(limit=5, offset=5)), BOT_RULES
        )
        assert [i["path"] for i in page1["items"]] != [i["path"] for i in page2["items"]]
        assert len(page1["items"]) == 5 and len(page2["items"]) == 5
        assert page1["total_paths"] == page2["total_paths"] == 16
        errors = service.seo_status_groups(
            conn, _filt(limit=1, offset=1), BOT_RULES, status_class="4xx"
        )
        assert errors["limit"] == 1 and errors["offset"] == 1 and len(errors["items"]) == 1
    finally:
        conn.close()


# --- T2a-D: SEO bot errors, AI-only paths, referrer 404s ---


def test_t2a_d_seo_status_groups_by_path_and_rule(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        redirects = service.seo_status_groups(conn, _filt(), BOT_RULES, status_class="3xx")
        clients = service.seo_status_groups(conn, _filt(), BOT_RULES, status_class="4xx")
        servers = service.seo_status_groups(conn, _filt(), BOT_RULES, status_class="5xx")
    finally:
        conn.close()
    assert redirects["total_groups"] == 2
    assert [(i["path"], i["rule_id"], i["requests"]) for i in redirects["items"]] == [
        ("/old", "bot-ai-gpt", 1),
        ("/old", "bot-search-google", 1),
    ]
    assert redirects["items"][0]["provider"] == "OpenAI"
    assert redirects["items"][0]["drilldown"] == {
        "bot": "bot-ai-gpt",
        "path_exact": "/old",
        "status_class": "3xx",
    }
    assert clients["total_groups"] == 3
    assert [(i["path"], i["rule_id"]) for i in clients["items"]] == [
        ("/gone", "bot-ai-gpt"),
        ("/missing-thing", "bot-ai-gpt"),
        ("/secret-leak-probe", "bot-auto-curl"),
    ]
    assert all(i["requests"] == 1 and i["bytes_total"] == 100 for i in clients["items"])
    assert servers["total_groups"] == 1
    assert servers["items"][0]["path"] == "/api/data"
    assert servers["items"][0]["rule_id"] == "bot-search-google"
    check = connect(db, read_only=True)
    try:
        with pytest.raises(ValueError):
            service.seo_status_groups(check, _filt(), BOT_RULES, status_class="2xx")
    finally:
        check.close()


def test_t2a_d_ai_only_paths_with_scope_and_caveat(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.ai_only_paths(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    assert result["total_paths"] == 3
    by_path = {item["path"]: item for item in result["items"]}
    assert set(by_path) == {"/ai-only-page", "/gone", "/zero2"}
    assert by_path["/ai-only-page"]["ai_requests"] == 2
    assert by_path["/ai-only-page"]["ai_bytes"] == 200
    assert by_path["/ai-only-page"]["rules"] == ["bot-ai-gpt", "bot-ai-oai-search"]
    assert by_path["/ai-only-page"]["providers"] == ["OpenAI"]
    assert by_path["/gone"]["rules"] == ["bot-ai-gpt"]
    comparison = result["comparison"]
    assert comparison["universe_paths"] == 18
    assert comparison["universe_requests"] == 24
    assert comparison["ai_observed_paths"] == 6
    assert comparison["other_observed_paths"] == 15
    assert comparison["selectors_removed"] == []
    assert result["vacuous"] is False
    assert any("never proof of absence" in str(lim) for lim in result["limitations"])
    assert any("training" in str(lim) for lim in result["limitations"])
    # Candidate scope is the unfiltered scope here, so both coverages agree.
    assert result["candidate"]["filters"]["bot"] is None
    assert result["candidate"]["coverage"]["unique_events"] == 24
    assert result["comparison"]["filters"]["traffic"] == "all"
    assert result["comparison"]["coverage"]["unique_events"] == 24


def test_t2a_d_ai_only_selectors_removed_not_narrowed(tmp_path):
    """Candidate selectors stay on the candidate side; only the universe widens."""
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        narrowed = service.ai_only_paths(
            conn, _filt(category="ai_crawler", bot="bot-ai-gpt"), BOT_RULES
        )
        plain = service.ai_only_paths(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    # Same universe (selectors removed there), but the candidate set stays
    # GPT-scoped: /ai-only-page counts only its GPT row here.
    assert narrowed["total_paths"] == plain["total_paths"] == 3
    assert sorted(narrowed["comparison"]["selectors_removed"]) == ["bot", "category"]
    assert narrowed["comparison"]["universe_requests"] == 24
    by_path = {item["path"]: item for item in narrowed["items"]}
    assert by_path["/ai-only-page"]["ai_requests"] == 1
    assert by_path["/ai-only-page"]["rules"] == ["bot-ai-gpt"]
    assert by_path["/ai-only-page"]["providers"] == ["OpenAI"]
    assert by_path["/ai-only-page"]["drilldown"] == {
        "path_exact": "/ai-only-page",
        "category": "ai_crawler",
    }
    # Distinct correctly scoped candidate vs comparison filters/coverage.
    assert narrowed["candidate"]["filters"]["bot"] == "bot-ai-gpt"
    assert narrowed["candidate"]["coverage"]["unique_events"] == 6
    assert narrowed["comparison"]["filters"]["bot"] is None
    assert narrowed["comparison"]["filters"]["category"] is None
    assert narrowed["comparison"]["coverage"]["unique_events"] == 24
    assert narrowed["filters"]["bot"] == "bot-ai-gpt"


def test_t2a_d_vacuous_universe_flagged(tmp_path):
    """A universe with only AI traffic is trivially AI-only: flag it."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "aionly.log").write_bytes(
        _extended_line(path="/a", ua=GPT_UA, minute=1)
        + _extended_line(path="/b", ua=GPT_UA, minute=2)
    )
    db = tmp_path / "aionly.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="ai",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="aionly.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="aionly.log",
        hmac_key=HMAC_KEY,
    )
    conn = connect(db, read_only=True)
    try:
        result = service.ai_only_paths(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    assert result["total_paths"] == 2
    assert result["comparison"]["other_observed_paths"] == 0
    assert result["vacuous"] is True
    assert any("trivially AI-only" in str(w) for w in result["warnings"])


def test_t2a_d_referrer_404_sanitized_split(tmp_path):
    db = _import_t2a_c(tmp_path)
    conn = connect(db, read_only=True)
    try:
        report = service.referrer_404s(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    assert report["total_groups"] == 3
    assert report["own_hosts"] == ["alias.example", SITE_HOST]
    by_host = {(i["referer_host"], i["target_path"]): i for i in report["items"]}
    ext = by_host[("external.example", "/missing-thing")]
    assert (ext["referer_scheme"], ext["referer_path"], ext["requests"]) == (
        "https",
        "/blog/post",
        1,
    )
    assert ext["internal"] is False
    internal = by_host[("alias.example", "/missing-thing")]
    assert internal["internal"] is True
    assert internal["referer_path"] == "/internal/page"
    leak = by_host[("external.example", "/secret-leak-probe")]
    assert leak["referer_path"] == "/x"
    assert leak["internal"] is False
    dumped = json.dumps(report)
    for secret in ("token=secret", "pw=hunter2", "user:pw", "utm=x", ":8443", "javascript:"):
        assert secret not in dumped
    assert "case/port/IDN" in report["host_matching"] or "ports" in report["host_matching"]


def test_t2a_d_exact_totals_beyond_scan_cap(tmp_path):
    """5100 distinct bot-404 paths: exact GROUP BY totals, no scan cap."""
    root = tmp_path / "logs"
    root.mkdir()
    lines = []
    for index in range(5100):
        lines.append(
            f"203.0.12.1 - - [27/Oct/2026:10:00:00 +0000] "
            f'"GET /cap-{index:05d} HTTP/1.1" 404 10 "-" "{GPT_UA}" '
            f'example.org - - - - "-"\n'
        )
    assert len(lines) > queries.MAX_DISTINCT_SCAN
    (root / "cap.log").write_bytes("".join(lines).encode())
    db = tmp_path / "cap.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="cap",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="cap.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="cap.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.records_inserted == 5100
    conn = connect(db, read_only=True)
    try:
        groups = service.seo_status_groups(
            conn, _filt(limit=100, offset=0), BOT_RULES, status_class="4xx"
        )
        assert groups["total_groups"] == 5100
        assert len(groups["items"]) == 100
        tail = service.seo_status_groups(
            conn, _filt(limit=100, offset=5000), BOT_RULES, status_class="4xx"
        )
        assert len(tail["items"]) == 100
        assert {i["path"] for i in groups["items"]}.isdisjoint({i["path"] for i in tail["items"]})
        only = service.ai_only_paths(conn, _filt(limit=100, offset=0), BOT_RULES)
        assert only["total_paths"] == 5100
        assert only["vacuous"] is True
    finally:
        conn.close()


CLAUDE_UA = "Mozilla/5.0 (compatible; Claude-SearchBot/1.0)"


def _import_p95_probe(tmp_path) -> Path:
    """201-path probe: 200 frequent 1ms paths plus one rare 10000ms path."""
    root = tmp_path / "logs"
    root.mkdir()
    lines = []
    for index in range(200):
        for repeat in range(2):
            lines.append(
                _extended_line(
                    path=f"/fast-{index:03d}",
                    request_time="0.001",
                    minute=(index * 2 + repeat) % 60,
                )
            )
    lines.append(_extended_line(path="/rarest-slowest", request_time="10.0", minute=59))
    (root / "probe.log").write_bytes(b"".join(lines))
    db = tmp_path / "p95.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="p95",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="probe.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="probe.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.records_inserted == 401
    return db


def test_t2a_fix1_p95_desc_is_exact_global_rank(tmp_path):
    """A rare slow endpoint tops p95_desc; pages beyond 200 stay global."""
    db = _import_p95_probe(tmp_path)
    conn = connect(db, read_only=True)
    try:
        top = service.slow_endpoints(
            conn, SlowEndpointsQuery(filt=_filt(limit=1), sort="p95_desc"), BOT_RULES
        )
        assert top["total_paths"] == 201
        assert top["meta"] == {"candidate_paths": 201, "ranking": "p95_desc"}
        assert [i["path"] for i in top["items"]] == ["/rarest-slowest"]
        assert top["items"][0]["measured"] == 1
        assert top["items"][0]["p95_ms"] == pytest.approx(10000.0)
        assert top["items"][0]["p50_ms"] == pytest.approx(10000.0)
        tail = service.slow_endpoints(
            conn,
            SlowEndpointsQuery(filt=_filt(limit=5, offset=200), sort="p95_desc"),
            BOT_RULES,
        )
        assert tail["total_paths"] == 201
        assert len(tail["items"]) == 1 and tail["items"][0]["path"] == "/fast-199"
        assert tail["items"][0]["p95_ms"] == pytest.approx(1.0)
        # An active filter narrows the global scope honestly.
        scoped = service.slow_endpoints(
            conn,
            SlowEndpointsQuery(filt=_filt(timing_min_ms=5000.0), sort="p95_desc"),
            BOT_RULES,
        )
        assert scoped["total_paths"] == 1
        assert [i["path"] for i in scoped["items"]] == ["/rarest-slowest"]
    finally:
        conn.close()


def test_t2a_fix1_p95_ties_zero_and_missing(tmp_path):
    """Equal P95 values break ties by path; zero is valid, missing excluded."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ties.log").write_bytes(
        _extended_line(path="/b-same", request_time="0.010", minute=1)
        + _extended_line(path="/a-same", request_time="0.010", minute=2)
        + _extended_line(path="/a-same", request_time="0.010", minute=3)
        + _extended_line(path="/zero", request_time="0.000", minute=4)
        + _extended_line(path="/absent", request_time="-", minute=5)
    )
    db = tmp_path / "ties.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="ties",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ties.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="ties.log",
        hmac_key=HMAC_KEY,
    )
    conn = connect(db, read_only=True)
    try:
        result = service.slow_endpoints(
            conn, SlowEndpointsQuery(filt=_filt(limit=10), sort="p95_desc"), BOT_RULES
        )
    finally:
        conn.close()
    assert result["total_paths"] == 3
    assert [i["path"] for i in result["items"]] == ["/a-same", "/b-same", "/zero"]
    assert result["items"][0]["p95_ms"] == pytest.approx(10.0)
    assert result["items"][0]["p50_ms"] == pytest.approx(10.0)
    assert result["items"][2]["p95_ms"] == pytest.approx(0.0)
    assert [i["path"] for i in result["items"] if i["measured"] == 2] == ["/a-same"]


def test_t2a_fix2_summary_and_overview_agree_on_timing(tmp_path):
    """Shared summary availability/counts match measured request timing."""
    db = _import_t2a_c(tmp_path)
    conn = connect(db)
    try:
        summary = service.summarize(conn, _filt(), BOT_RULES)
        overview = service.performance_overview(conn, _filt(), BOT_RULES)
        assert summary["duration"] == {"available": True, "measured": 21}
        assert overview["latency_available"] is True
        assert overview["latency_ms"]["measured"] == 21
        assert summary["duration"]["measured"] == overview["latency_ms"]["measured"]
        # Combined-only data stays unavailable on both read paths.
        missing = service.summarize(conn, _filt(path_exact="/gone"), BOT_RULES)
        assert missing["duration"] == {
            "available": False,
            "measured": 0,
            "reason": "no_measured_request_timing",
        }
        # An explicitly stored legacy duration is acknowledged, never
        # rewritten: request timing stays unavailable, legacy is counted.
        conn.execute("UPDATE requests SET duration_ms = 5.0 WHERE path = '/plain-absent'")
        conn.commit()
        legacy = service.summarize(conn, _filt(path_exact="/plain-absent"), BOT_RULES)
        assert legacy["duration"]["available"] is False
        assert legacy["duration"]["measured"] == 0
        assert legacy["duration"]["legacy_measured"] == 1
        assert legacy["duration"]["reason"] == "legacy_duration_only:no_measured_request_timing"
        legacy_overview = service.performance_overview(
            conn, _filt(path_exact="/plain-absent"), BOT_RULES
        )
        assert legacy_overview["latency_available"] is False
        assert legacy_overview["latency_ms"]["measured"] == 0
    finally:
        conn.close()


def _import_ai_four(tmp_path) -> Path:
    """Confirmed 4-row scope: GPT-only, Claude-only, shared GPT+browser."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ai4.log").write_bytes(
        _extended_line(path="/gpt-only", ua=GPT_UA, request_time="0.010", minute=1)
        + _extended_line(path="/claude-only", ua=CLAUDE_UA, request_time="0.011", minute=2)
        + _extended_line(path="/shared", ua=GPT_UA, request_time="0.012", minute=3)
        + _extended_line(path="/shared", ua=BROWSER_UA, request_time="0.013", minute=4)
    )
    db = tmp_path / "ai4.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="ai4",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ai4.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="ai4.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.records_inserted == 4
    return db


def test_t2a_fix3_gpt_filter_keeps_gpt_candidates_only(tmp_path):
    """bot-ai-gpt returns /gpt-only: never /claude-only, never shared browser."""
    db = _import_ai_four(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.ai_only_paths(conn, _filt(bot="bot-ai-gpt"), BOT_RULES)
    finally:
        conn.close()
    assert result["total_paths"] == 1
    (item,) = result["items"]
    assert item["path"] == "/gpt-only"
    assert item["ai_requests"] == 1 and item["rules"] == ["bot-ai-gpt"]
    assert item["providers"] == ["OpenAI"]
    assert item["drilldown"] == {"path_exact": "/gpt-only", "category": "ai_crawler"}
    # The comparison universe still sees all 4 rows / 3 paths.
    assert result["comparison"]["universe_requests"] == 4
    assert result["comparison"]["universe_paths"] == 3
    assert result["comparison"]["other_observed_paths"] == 1
    assert result["comparison"]["selectors_removed"] == ["bot"]
    assert result["comparison"]["filters"]["bot"] is None
    assert result["comparison"]["coverage"]["unique_events"] == 4
    # Candidate coverage is GPT-scoped (2 rows), not the universe.
    assert result["candidate"]["filters"]["bot"] == "bot-ai-gpt"
    assert result["candidate"]["coverage"]["unique_events"] == 2
    assert result["coverage"]["unique_events"] == 2
    assert result["vacuous"] is False


def test_t2a_fix3_provider_category_traffic_scopes(tmp_path):
    """Provider/category/traffic candidates widen only the universe."""
    db = _import_ai_four(tmp_path)
    conn = connect(db, read_only=True)
    try:
        openai = service.ai_only_paths(conn, _filt(provider="OpenAI"), BOT_RULES)
        anthropic = service.ai_only_paths(conn, _filt(provider="Anthropic"), BOT_RULES)
        category = service.ai_only_paths(conn, _filt(category="ai_crawler"), BOT_RULES)
        claimed = service.ai_only_paths(conn, _filt(traffic="claimed_bot"), BOT_RULES)
    finally:
        conn.close()
    assert [i["path"] for i in openai["items"]] == ["/gpt-only"]
    assert openai["comparison"]["universe_requests"] == 4
    assert [i["path"] for i in anthropic["items"]] == ["/claude-only"]
    assert anthropic["items"][0]["providers"] == ["Anthropic"]
    assert sorted(i["path"] for i in category["items"]) == ["/claude-only", "/gpt-only"]
    assert sorted(i["path"] for i in claimed["items"]) == ["/claude-only", "/gpt-only"]
    assert claimed["comparison"]["selectors_removed"] == ["traffic"]


def test_t2a_fix3_incompatible_selectors_rejected(tmp_path):
    """Selectors that cannot hold AI candidates raise instead of widening."""
    db = _import_ai_four(tmp_path)
    conn = connect(db, read_only=True)
    try:
        for bad in (
            _filt(traffic="browser_like"),
            _filt(traffic="unknown"),
            _filt(traffic="other_automation"),
            _filt(bot="bot-search-google"),
            _filt(category="search_crawler"),
            _filt(provider="Google"),
            _filt(purpose="Search Indexer"),
        ):
            with pytest.raises(ValueError):
                service.ai_only_paths(conn, bad, BOT_RULES)
    finally:
        conn.close()


def test_t2a_fix3_no_other_traffic_scope_stays_vacuous(tmp_path):
    """An AI-only universe is flagged vacuous, never silent proof."""
    db = _import_ai_four(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.ai_only_paths(conn, _filt(path_exact="/gpt-only"), BOT_RULES)
    finally:
        conn.close()
    assert result["total_paths"] == 1
    assert result["comparison"]["other_observed_paths"] == 0
    assert result["vacuous"] is True
    assert any("trivially AI-only" in str(w) for w in result["warnings"])


_MANY_MIMES = ["text/html", "image/png", "application/json", "-"]


def _import_many_hosts(tmp_path, count: int, sources: int = 4) -> Path:
    """``count`` distinct logged hosts across several allowed sources.

    One source allows at most 64 hosts, so high cardinality spans
    several sources of the same site (plus shared HIT/Unknown rows in
    the first file). Every generated host is allowlisted in its own
    source: nothing here is a foreign skip.
    """
    root = tmp_path / "logs"
    root.mkdir()
    db = tmp_path / "hosts.sqlite3"
    made = 0
    per = (count + sources - 1) // sources
    for slot in range(sources):
        batch = min(per, count - made)
        hosts = [f"host-{slot:02d}-{index:04d}.example" for index in range(batch)]
        lines = []
        for index, host in enumerate(hosts):
            lines.append(
                _extended_line(
                    path=f"/h-{slot:02d}-{index:04d}",
                    host=host,
                    mime=_MANY_MIMES[made % len(_MANY_MIMES)],
                    request_time="0.013",
                    minute=made % 60,
                )
            )
            made += 1
        if slot == 0:
            lines.append(
                _extended_line(
                    path="/hit",
                    host="example.org",
                    cache="HIT",
                    request_time="0.010",
                    minute=59,
                )
            )
            lines.append(
                _extended_line(
                    path="/hit",
                    host="example.org",
                    cache="HIT",
                    request_time="0.011",
                    minute=58,
                )
            )
            lines.append(
                _extended_line(path="/unknown-host", host="-", request_time="0.012", minute=57)
            )
        name = f"hosts-{slot}.log"
        (root / name).write_bytes(b"".join(lines))
        imported = run_import(
            db,
            source=SourceConfig(
                source_id=f"hosts-{slot}",
                format_id=NGINX_EXTENDED,
                allowed_root=root,
                relative_path=name,
                allowed_hosts=[SITE_HOST, *hosts],
            ),
            site_id=SITE,
            site_name="T2a",
            site_hostname=SITE_HOST,
            server_type="nginx",
            path_alias=name,
            hmac_key=HMAC_KEY,
        )
        assert imported.records_inserted == len(lines)
        assert imported.records_skipped_foreign == 0
    assert made == count
    return db


def test_t2a_fix4_host_distribution_bounded_with_exact_totals(tmp_path):
    """High-cardinality hosts page with exact totals; Unknown stays separate."""
    db = _import_many_hosts(tmp_path, 250)
    conn = connect(db, read_only=True)
    try:
        items, total, page = queries.host_distribution(conn, _filt(), None)
        full = service.performance_overview(conn, _filt(), BOT_RULES)
    finally:
        conn.close()
    # 250 distinct hosts + example.org + Unknown = 252 values, 253 rows.
    assert total == 253
    assert page["total_values"] == 252
    assert page["truncated"] is True
    assert page["other_requests"] > 0
    assert sum(i["requests"] for i in items) + page["other_requests"] == total
    assert len(items) == page["shown"] == 100 + 1
    # Unknown is always the last bucket and count-correct.
    assert items[-1] == {"value": "Unknown", "requests": 1}
    assert page["unknown_requests"] == 1
    assert [i["value"] for i in items[:-1]] == sorted(i["value"] for i in items[:-1])
    hosts = full["logged_hosts"]
    assert hosts["total"] == 253 and hosts["truncated"] is True
    assert hosts["unknown_requests"] == 1
    # A later page still carries exact totals and the Unknown bucket.
    conn = connect(db, read_only=True)
    try:
        tail_items, tail_total, tail_page = queries.host_distribution(
            conn, _filt(), None, limit=100, offset=200
        )
    finally:
        conn.close()
    assert tail_total == 253 and tail_page["total_values"] == 252
    assert tail_items[-1] == {"value": "Unknown", "requests": 1}
    assert sum(i["requests"] for i in tail_items) + tail_page["other_requests"] == 253


def test_t2a_fix4_unknown_last_at_ties_and_hit_numerator_kept(tmp_path):
    """Unknown sorts last at count ties; HIT numerator survives a top page."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "ties.log").write_bytes(
        _extended_line(path="/a", cache="MISS", request_time="0.010", minute=1)
        + _extended_line(path="/b", cache="MISS", request_time="0.011", minute=2)
        + _extended_line(path="/c", cache="HIT", request_time="0.012", minute=3)
        + _extended_line(path="/d", cache="-", request_time="0.013", minute=4)
    )
    db = tmp_path / "hit.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="hit",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ties.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="ties.log",
        hmac_key=HMAC_KEY,
    )
    conn = connect(db, read_only=True)
    try:
        cache = queries.cache_distribution(conn, _filt(), None, limit=1)
        by_value = {item["value"]: item for item in cache["items"]}
    finally:
        conn.close()
    # Top-1 page shows only MISS plus the separate Unknown bucket; the
    # HIT numerator/denominator are still whole-scope exact even though
    # HIT sits outside the displayed top group.
    assert [i["value"] for i in cache["items"]] == ["MISS", "Unknown"]
    assert cache["shown"] == 2 and cache["truncated"] is True
    assert cache["other_requests"] == 1
    assert cache["hit_requests"] == 1
    assert cache["hit_ratio"] == pytest.approx(1 / 3)
    assert cache["cache_measured"] == 3 and cache["cache_missing"] == 1
    assert by_value["Unknown"]["requests"] == 1


def test_t2a_fix4_mime_bounded_with_other_remainder(tmp_path):
    """MIME cross-tab pages with an exact Other remainder and Unknown last."""
    db = _import_many_hosts(tmp_path, 150)
    conn = connect(db, read_only=True)
    try:
        mime = queries.mime_resource_breakdown(conn, _filt(), None, limit=2)
        mime_unknown_free = queries.mime_resource_breakdown(
            conn, _filt(mime_type="text/html"), None
        )
    finally:
        conn.close()
    # Four pairs total: NULL-mime/page is the largest (40) yet sorts last,
    # so the top-2 known page heads the response and Unknown follows separately.
    assert mime["total"] == 153
    assert mime["total_values"] == 4
    assert mime["truncated"] is True
    assert [(i["mime_type"], i["requests"]) for i in mime["items"]] == [
        ("image/png", 38),
        ("text/html", 38),
        ("Unknown", 40),
    ]
    assert mime["unknown_requests"] == 40 and mime["unknown_pairs"] == 1
    assert sum(i["requests"] for i in mime["items"]) + mime["other_requests"] == 153
    assert mime["other_requests"] == 153 - 116
    assert mime_unknown_free["total_values"] == 1
    assert mime_unknown_free["truncated"] is False


def _import_referrer_ties(tmp_path) -> Path:
    """Tied 404 groups across pages, internal/external sources, edge fields."""
    root = tmp_path / "logs"
    root.mkdir()
    lines = b""
    # Tied groups: same (host, target) count, differing scheme/path must
    # order deterministically across pages instead of only by host/target.
    lines += _extended_line(
        path="/tie", status=404, referer="http://tied.example/a", ua="-", minute=1
    )
    lines += _extended_line(
        path="/tie", status=404, referer="https://tied.example/a", ua="-", minute=2
    )
    lines += _extended_line(
        path="/tie", status=404, referer="http://tied.example/b", ua="-", minute=3
    )
    # Missing referrer path (bare host) and internal alias source.
    lines += _extended_line(
        path="/bare", status=404, referer="https://shop.example", ua="-", minute=4
    )
    lines += _extended_line(
        path="/gone", status=404, referer="https://external.example/p", ua="-", minute=5
    )
    lines += _extended_line(
        path="/gone", status=404, referer="https://external.example/q", ua="-", minute=6
    )
    (root / "ref.log").write_bytes(lines)
    db = tmp_path / "ref.sqlite3"
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="ref",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="ref.log",
            allowed_hosts=[SITE_HOST, "shop.example"],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="ref.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.records_inserted == 6
    # Adversarial separator bytes in a stored field (simulating legacy
    # bytes the ingestion-time control-char rejection would now drop):
    # a delimiter-collision tuple encoding would merge groups here.
    writer = connect(db)
    try:
        writer.execute(
            "UPDATE requests SET referer_path = '/q' || CHAR(31) || 'extra'"
            " WHERE path = '/gone' AND referer_path = '/q'"
        )
        writer.commit()
        assert writer.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 6
    finally:
        writer.close()
    return db


def test_t2a_fix5_referrer_tuples_exact_and_stable(tmp_path):
    """Tuple totals are exact; every grouping key orders ties; pages agree."""
    db = _import_referrer_ties(tmp_path)
    conn = connect(db, read_only=True)
    try:
        items, total = queries.referrer_404_targets(conn, _filt(limit=10), None)
        page1, total1 = queries.referrer_404_targets(conn, _filt(limit=2, offset=0), None)
        page2, total2 = queries.referrer_404_targets(conn, _filt(limit=2, offset=2), None)
        page3, total3 = queries.referrer_404_targets(conn, _filt(limit=2, offset=4), None)
    finally:
        conn.close()
    # Six rows, six distinct (host, scheme, path, target) tuples: no
    # delimiter-collision merge of the \x1f-bearing fields.
    assert total == total1 == total2 == total3 == 6
    assert len(items) == 6
    keys = [
        (i["referer_host"], i["referer_scheme"], i["referer_path"], i["target_path"]) for i in items
    ]
    assert len(set(keys)) == 6
    # Full stable order across pages: count, host, scheme, path, target.
    assert [items.index(i) for page in (page1, page2, page3) for i in page] == list(range(6))
    order = [(i["requests"], i["referer_host"]) for i in items]
    assert order == sorted(order, key=lambda t: (-t[0], t[1]))
    # The tied (tied.example, /tie) groups separate by scheme before path.
    tied = [i for i in items if i["referer_host"] == "tied.example"]
    assert [(i["referer_scheme"], i["referer_path"]) for i in tied] == [
        ("http", "/a"),
        ("http", "/b"),
        ("https", "/a"),
    ]


def test_t2a_fix5_referrer_relation_filters_in_sql(tmp_path):
    """internal/external selectors filter in SQL with matching totals."""
    db = _import_referrer_ties(tmp_path)
    conn = connect(db, read_only=True)
    try:
        report = service.referrer_404s(conn, _filt(), None)
        internal = service.referrer_404s(conn, _filt(), None, relation="internal")
        external = service.referrer_404s(conn, _filt(), None, relation="external")
    finally:
        conn.close()
    assert report["relation"] == "all" and report["total_groups"] == 6
    assert all("internal" in i for i in report["items"])
    assert internal["total_groups"] == 1
    assert [i["referer_host"] for i in internal["items"]] == ["shop.example"]
    assert all(i["internal"] for i in internal["items"])
    assert external["total_groups"] == 5
    assert all(not i["internal"] for i in external["items"])
    assert internal["total_groups"] + external["total_groups"] == report["total_groups"]
    check = connect(db, read_only=True)
    try:
        with pytest.raises(ValueError):
            service.referrer_404s(check, _filt(), None, relation="sometimes")
    finally:
        check.close()


def test_t2a_fix6_resolve_explicit_hosts_extends_primary():
    """--host-alias extends the primary; --host-filter replaces it."""
    from app.db.cli import _resolve_explicit_hosts

    assert _resolve_explicit_hosts(
        site_hostname="example.org", host_filter=None, host_alias=None, vhost_bearing=True
    ) == ["example.org"]
    assert (
        _resolve_explicit_hosts(
            site_hostname="example.org", host_filter=None, host_alias=None, vhost_bearing=False
        )
        == []
    )
    assert _resolve_explicit_hosts(
        site_hostname="example.org",
        host_filter=None,
        host_alias=["shop.example"],
        vhost_bearing=True,
    ) == ["example.org", "shop.example"]
    assert _resolve_explicit_hosts(
        site_hostname="example.org",
        host_filter=["other.example"],
        host_alias=None,
        vhost_bearing=True,
    ) == ["other.example"]
    assert _resolve_explicit_hosts(
        site_hostname="example.org",
        host_filter=["other.example"],
        host_alias=["shop.example"],
        vhost_bearing=True,
    ) == ["other.example", "shop.example"]
    assert _resolve_explicit_hosts(
        site_hostname="example.org",
        host_filter=None,
        host_alias=["Example.ORG", "shop.example", "shop.example"],
        vhost_bearing=True,
    ) == ["example.org", "shop.example"]


def _host_fixture_lines() -> bytes:
    return (
        _extended_line(path="/primary", host="example.org", minute=1)
        + _extended_line(path="/alias", host="shop.example", minute=2)
        + _extended_line(path="/foreign", host="foreign.example", minute=3)
    )


def test_t2a_fix6_alias_alone_keeps_primary_on_import_and_reprocess(tmp_path, monkeypatch, capsys):
    """--host-alias alone counts primary+alias, skips foreign, binds one site."""
    import json

    from app.db import cli as cli_mod

    root = tmp_path / "logs"
    root.mkdir()
    (root / "hosts.log").write_bytes(_host_fixture_lines())
    db = tmp_path / "cli.sqlite3"
    monkeypatch.setenv("HMAC_KEY", "parity-cli-test-key")
    base = [
        "--source-id",
        "cli-source",
        "--format",
        "nginx_extended",
        "--root",
        str(root),
        "--path",
        "hosts.log",
        "--site-hostname",
        "example.org",
        "--host-alias",
        "shop.example",
    ]
    capsys.readouterr()
    assert cli_mod.main(["--db", str(db), "import", *base]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["records_inserted"] == 2 and payload["records_skipped_foreign"] == 1
    check = connect(db, read_only=True)
    try:
        assert check.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 2
        assert {row[0] for row in check.execute("SELECT path FROM requests")} == {
            "/primary",
            "/alias",
        }
        assert check.execute("SELECT COUNT(DISTINCT site_id) FROM log_sources").fetchone()[0] == 1
        assert json.loads(check.execute("SELECT allowed_hosts FROM log_sources").fetchone()[0]) == [
            "example.org",
            "shop.example",
        ]
    finally:
        check.close()
    # A repeated import inserts nothing new and binds no second site.
    capsys.readouterr()
    assert cli_mod.main(["--db", str(db), "import", *base]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["records_inserted"] == 0
    # Reprocess with the same alias keeps the persisted primary+alias set.
    repro = [
        "--source-id",
        "cli-source",
        "--format",
        "nginx_extended",
        "--root",
        str(root),
        "--path",
        "hosts.log",
        "--site-hostname",
        "example.org",
        "--host-alias",
        "shop.example",
    ]
    capsys.readouterr()
    assert cli_mod.main(["--db", str(db), "reprocess", *repro]) == 0
    reprocessed = json.loads(capsys.readouterr().out)
    # The never-stored foreign line matches no stored row, so reprocess
    # verifies the two stored rows and persists the alias set unchanged.
    assert reprocessed["status"] == "completed" and reprocessed["rows_verified"] == 2
    assert reprocessed["rows_skipped_foreign"] == 0
    verify = connect(db, read_only=True)
    try:
        assert json.loads(
            verify.execute("SELECT allowed_hosts FROM log_sources").fetchone()[0]
        ) == ["example.org", "shop.example"]
        assert verify.execute("SELECT COUNT(DISTINCT site_id) FROM log_sources").fetchone()[0] == 1
    finally:
        verify.close()


def test_t2a_fix6_host_filter_replaces_primary(tmp_path, monkeypatch, capsys):
    """An explicit --host-filter is the whole set: primary is not added."""
    import json

    from app.db import cli as cli_mod

    root = tmp_path / "logs"
    root.mkdir()
    (root / "hosts.log").write_bytes(_host_fixture_lines())
    db = tmp_path / "filter.sqlite3"
    monkeypatch.setenv("HMAC_KEY", "parity-cli-test-key")
    argv = [
        "--db",
        str(db),
        "import",
        "--source-id",
        "filter-source",
        "--format",
        "nginx_extended",
        "--root",
        str(root),
        "--path",
        "hosts.log",
        "--site-hostname",
        "example.org",
        "--host-filter",
        "shop.example",
    ]
    capsys.readouterr()
    assert cli_mod.main(argv) == 0, capsys.readouterr().err
    payload = json.loads(capsys.readouterr().out)
    assert payload["records_inserted"] == 1 and payload["records_skipped_foreign"] == 2
    check = connect(db, read_only=True)
    try:
        assert {row[0] for row in check.execute("SELECT path FROM requests")} == {"/alias"}
    finally:
        check.close()


def test_t2a_fix7_exact_path_selector_reproduces_single_group(tmp_path):
    """path_exact matches one stored path; prefix stays a widening exploration."""
    root = tmp_path / "logs"
    root.mkdir()
    (root / "prefix.log").write_bytes(
        _extended_line(path="/old", status=301, ua=GPT_UA, minute=1)
        + _extended_line(path="/old-extra", status=301, ua=GPT_UA, minute=2)
        + _extended_line(path="/old/child", status=301, ua=GPT_UA, minute=3)
    )
    db = tmp_path / "prefix.sqlite3"
    run_import(
        db,
        source=SourceConfig(
            source_id="prefix",
            format_id=NGINX_EXTENDED,
            allowed_root=root,
            relative_path="prefix.log",
            allowed_hosts=[SITE_HOST],
        ),
        site_id=SITE,
        site_name="T2a",
        site_hostname=SITE_HOST,
        server_type="nginx",
        path_alias="prefix.log",
        hmac_key=HMAC_KEY,
    )
    conn = connect(db, read_only=True)
    try:
        exact = service.seo_status_groups(
            conn, _filt(path_exact="/old"), BOT_RULES, status_class="3xx"
        )
        prefixed = service.seo_status_groups(
            conn, _filt(path_prefix="/old"), BOT_RULES, status_class="3xx"
        )
        assert exact["total_groups"] == 1
        assert [i["path"] for i in exact["items"]] == ["/old"]
        assert prefixed["total_groups"] == 3
        drilldown = exact["items"][0]["drilldown"]
        assert drilldown == {"bot": "bot-ai-gpt", "path_exact": "/old", "status_class": "3xx"}
        # The drilldown evidence filter reproduces exactly the reported group.
        evidence = service.seo_status_groups(
            conn,
            _filt(bot=drilldown["bot"], path_exact=drilldown["path_exact"]),
            BOT_RULES,
            status_class="3xx",
        )
        assert evidence["total_groups"] == 1 and evidence["items"][0]["requests"] == 1
        # A prefix drilldown is explicitly wider than the reported row.
        wide = service.seo_status_groups(
            conn,
            _filt(bot=drilldown["bot"], path_prefix=drilldown["path_exact"]),
            BOT_RULES,
            status_class="3xx",
        )
        assert wide["total_groups"] == 3
        # The shared contract carries the selector everywhere (round-trip).
        clone = AnalyticsFilter.model_validate(_filt(path_exact="/old").model_dump())
        assert clone == _filt(path_exact="/old")
        assert service._filter_dict(clone)["path_exact"] == "/old"
        with pytest.raises(ValueError):
            _filt(path_exact="/other", path_prefix="/old")
        with pytest.raises(ValueError):
            _filt(path_exact="   ")
    finally:
        conn.close()

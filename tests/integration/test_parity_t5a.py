"""T5a integration tests: genuine offline country enrichment (PAR-09).

End-to-end coverage over temporary synthetic databases with an
in-memory fake MMDB reader (no database file, no network, no real
addresses). The globally routable addresses below are TEST-ONLY
synthetic lookup inputs with hand-derived expectations, never real
runtime observations; the documentation/private addresses stay
Unknown by design.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient

from app.analytics import service as analytics_service
from app.analytics.contracts import AnalyticsFilter, ExplorerQuery, TimeWindow
from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db import cli as db_cli
from app.db.database import writer_transaction
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.db.reprocess import run_reprocess
from app.ingestion.geoip import (
    GEO_SOURCE_DBIP,
    GEO_STATUS_HIT,
    GEO_STATUS_UNAVAILABLE,
    GEO_STATUS_UNKNOWN,
    CountryLookup,
    GeoipError,
)
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"t5a-integration-hmac-key"

ROOT = Path(__file__).resolve().parent.parent.parent

FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)

# TEST-ONLY synthetic country map for the fake reader below.
TEST_RECORDS = {
    "8.8.8.8": {"country_code": "US"},
    "1.1.1.1": {"country_code": "AU"},
    "2001:4860:4860::8888": {"country": {"iso_code": "US"}},
}

LINES = [
    # US hit: 2 requests, 1x 500, 3000 bytes.
    '8.8.8.8 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 1000 "-" "T5a/1.0"',
    '8.8.8.8 - - [27/Oct/2026:10:01:00 +0000] "GET /b HTTP/1.1" 500 2000 "-" "T5a/1.0"',
    # AU hit: 1 request, 1x 404, 500 bytes.
    '1.1.1.1 - - [27/Oct/2026:11:00:00 +0000] "GET /c HTTP/1.1" 404 500 "-" "T5a/1.0"',
    # Documentation + private: always Unknown (2 requests, 150 bytes).
    '203.0.113.5 - - [27/Oct/2026:12:00:00 +0000] "GET /d HTTP/1.1" 200 100 "-" "T5a/1.0"',
    '10.0.0.2 - - [27/Oct/2026:12:01:00 +0000] "GET /e HTTP/1.1" 200 50 "-" "T5a/1.0"',
    # US hit over IPv6: 1 request, 1x 503, 300 bytes.
    '2001:4860:4860::8888 - - [27/Oct/2026:13:00:00 +0000] "GET /f HTTP/1.1" 503 300 "-" "T5a/1.0"',
]


class FakeReader:
    def __init__(self, records):
        self._records = dict(records)

    def metadata(self):
        class _Meta:
            database_type = "DBIP-Country-Lite"
            build_epoch = 1761955200  # 2026-11-01T00:00:00Z

        return _Meta()

    def get(self, ip_text):
        return self._records.get(ip_text)

    def close(self):
        pass


def _lookup(records=None):
    reader = FakeReader(TEST_RECORDS if records is None else records)
    return CountryLookup(
        reader,
        source=GEO_SOURCE_DBIP,
        release="2026-11",
        database_type="DBIP-Country-Lite",
        available=True,
    )


def _filt(**overrides):
    base = {"site_id": "default", "window": TimeWindow(time_from=FROM, time_to=TO)}
    base.update(overrides)
    return AnalyticsFilter(**base)


@pytest.fixture
def t5a(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5a-session-secret")
    monkeypatch.setenv("HMAC_KEY", "t5a-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t5a.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "t5a.sqlite3"
    migrate(db)
    with _lookup() as lookup:
        report = run_import(
            db,
            source=SourceConfig(
                source_id="t5a",
                format_id="nginx_combined",
                allowed_root=root,
                relative_path="t5a.log",
            ),
            site_id="default",
            site_name="T5a",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="t5a.log",
            hmac_key=HMAC_KEY,
            country_lookup=lookup,
        )
    assert report.lines_accepted == 6, report
    assert report.geoip_available is True
    assert report.geoip_source == GEO_SOURCE_DBIP
    assert report.geoip_release == "2026-11"
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
        _, token = issue_token(conn, name="t5a", site_id="default")
    from app.analytics.rules import load_rules
    from app.main import create_app

    rules = (
        load_rules(ROOT / "config" / "bot_rules.yaml").rules
        + load_rules(ROOT / "config" / "security_rules.yaml").rules
    )
    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    return {"client": client, "db": db, "token": token, "rules": rules}


def _rows(db):
    with writer_transaction(db) as conn:
        return conn.execute(
            "SELECT client_pseudonym, country_code, geo_source, geo_release, geo_status"
            " FROM requests ORDER BY ts_utc"
        ).fetchall()


def test_import_enriches_exact_country_breakdown(t5a):
    rows = _rows(t5a["db"])
    assert [row[1] for row in rows] == ["US", "US", "AU", None, None, "US"]
    assert {row[4] for row in rows} == {GEO_STATUS_HIT, GEO_STATUS_UNKNOWN}
    assert all(row[2] == GEO_SOURCE_DBIP for row in rows if row[4] == GEO_STATUS_HIT)
    assert all(row[3] == "2026-11" for row in rows if row[4] == GEO_STATUS_HIT)

    with writer_transaction(t5a["db"]) as conn:
        result = analytics_service.country_breakdown(conn, _filt(), None)
    by_country = {item["country"]: item for item in result["items"]}
    # Hand-derived: US 3 requests / 0x4xx / 2x5xx / 3300 bytes;
    # AU 1 / 1 / 0 / 500; Unknown 2 / 0 / 0 / 150.
    assert by_country["US"]["requests"] == 3
    assert by_country["US"]["errors_4xx"] == 0
    assert by_country["US"]["errors_5xx"] == 2
    assert by_country["US"]["bytes_total"] == 3300
    assert by_country["AU"] == {
        "country": "AU",
        "requests": 1,
        "errors_4xx": 1,
        "errors_5xx": 0,
        "bytes_total": 500,
    }
    assert by_country["Unknown"]["requests"] == 2
    assert by_country["Unknown"]["bytes_total"] == 150
    assert result["geo"]["with_country"] == 4
    assert result["geo"]["unknown"] == 2
    assert result["geo"]["unavailable"] == 0
    assert result["attribution"]["url"] == "https://db-ip.com"
    assert result["attribution"]["text"] == "IP Geolocation by DB-IP"


def test_country_selector_shared_across_consumers(t5a):
    db, rules = t5a["db"], t5a["rules"]
    with writer_transaction(db) as conn:
        us_summary = analytics_service.summarize(conn, _filt(country="US"), rules)
        assert us_summary["totals"]["requests"] == 3
        unknown_summary = analytics_service.summarize(conn, _filt(country="UNKNOWN"), rules)
        assert unknown_summary["totals"]["requests"] == 2
        us_rows = analytics_service.request_explorer(
            conn, ExplorerQuery(filt=_filt(country="US"), sort="newest"), rules
        )
        assert us_rows["total_rows"] == 3
        all_rows = analytics_service.request_explorer(
            conn, ExplorerQuery(filt=_filt(), sort="newest"), rules
        )
        assert all_rows["total_rows"] == 6
        us_breakdown = analytics_service.country_breakdown(conn, _filt(country="US"), rules)
        assert [item["country"] for item in us_breakdown["items"]] == ["US"]
        # Saved-view recall replays the same filtered read.
        from app.web import routes as web_routes

        normalized, error = web_routes._validate_saved_target(
            "/requests",
            "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
            "&to=2026-10-28T00:00:00%2B00:00&tz=UTC&country=US",
        )
        assert error is None and "country=US" in normalized
        # Explicit empty country never selects Unknown: the contract
        # rejects it instead of silently widening.
        with pytest.raises(ValidationError):
            _filt(country="")


def test_api_country_filter_export_and_attribution(t5a):
    client, token = t5a["client"], t5a["token"]
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "site_id": "default",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
    }
    countries = client.get("/api/v1/countries", params=params, headers=headers)
    assert countries.status_code == 200, countries.text[:300]
    body = countries.json()
    assert body["filters"]["country"] is None
    assert body["geo"]["with_country"] == 4
    assert body["attribution"] == {
        "text": "IP Geolocation by DB-IP",
        "url": "https://db-ip.com",
        "database": "DB-IP Country Lite",
        "license": "CC BY 4.0",
    }
    us_only = client.get("/api/v1/countries", params={**params, "country": "us"}, headers=headers)
    assert us_only.status_code == 200, us_only.text[:300]
    assert us_only.json()["filters"]["country"] == "US"
    assert [item["country"] for item in us_only.json()["items"]] == ["US"]
    unknown_only = client.get(
        "/api/v1/countries", params={**params, "country": "UNKNOWN"}, headers=headers
    )
    assert unknown_only.status_code == 200
    assert [item["country"] for item in unknown_only.json()["items"]] == ["Unknown"]
    hostile = client.get("/api/v1/countries", params={**params, "country": "XX1"}, headers=headers)
    assert hostile.status_code == 400
    assert hostile.json()["code"] == "invalid_request"
    assert "XX1" not in hostile.text
    # Export carries the safe country outcome, never the original address.
    export = client.get(
        "/api/v1/exports/requests", params={**params, "format": "csv"}, headers=headers
    )
    assert export.status_code == 200
    text = export.text
    assert "country_code" in text.splitlines()[0]
    assert "8.8.8.8" not in text and "1.1.1.1" not in text
    assert "2001:4860:4860::8888" not in text
    assert ",US," in text and ",AU," in text


def test_ai_tool_country_scope_and_hostile_args(t5a):
    from app.ai.tools import definitions as tool_defs

    filt = _filt(country="us")
    assert filt.country == "US"
    hostile = {
        "site_id": "default",
        "time_from": FROM,
        "time_to": TO,
        "country": "XX1",
        "limit": 5,
        "offset": 0,
        "bucket": "day",
    }
    with pytest.raises((ValidationError, tool_defs.ToolError)):
        tool_defs.ToolArguments(**hostile)
    with writer_transaction(t5a["db"]) as conn:
        scoped = analytics_service.summarize(conn, filt, None)
    assert scoped["totals"]["requests"] == 3


def test_saved_view_country_roundtrip_and_reject():
    from app.web import routes as web_routes

    base = (
        "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
        "&to=2026-10-28T00:00:00%2B00:00&tz=UTC&country=de"
    )
    normalized, error = web_routes._validate_saved_target("/requests", base)
    assert error is None
    assert "country=DE" in normalized
    assert "csrf_token" not in normalized and "raw_ip" not in normalized
    unknown_qs, error = web_routes._validate_saved_target(
        "/requests", base.replace("country=de", "country=UNKNOWN")
    )
    assert error is None
    assert "country=UNKNOWN" in unknown_qs
    _normalized, error = web_routes._validate_saved_target(
        "/requests", base.replace("country=de", "country=XX1")
    )
    assert error is not None
    # Blank country stays no filter (shared transport rule), so it
    # validates and is dropped from the stored query, never Unknown.
    blanked, error = web_routes._validate_saved_target(
        "/requests", base.replace("country=de", "country=")
    )
    assert error is None
    assert "country" not in blanked


def test_missing_db_unavailable_and_required_fails_before_writes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t5a.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "t5a_nodb.sqlite3"
    migrate(db)
    report = run_import(
        db,
        source=SourceConfig(
            source_id="t5a",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="t5a.log",
        ),
        site_id="default",
        site_name="T5a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="t5a.log",
        hmac_key=HMAC_KEY,
    )
    assert report.lines_accepted == 6
    assert report.geoip_available is False
    rows = _rows(db)
    assert all(row[1] is None for row in rows)
    # Globally routable rows record unavailable (no database read them);
    # non-routable documentation/private rows stay unknown without any
    # database read, exactly as with a configured lookup.
    assert {row[4] for row in rows} == {GEO_STATUS_UNAVAILABLE, GEO_STATUS_UNKNOWN}
    with writer_transaction(db) as conn:
        result = analytics_service.country_breakdown(conn, _filt(), None)
    assert [item["country"] for item in result["items"]] == ["Unknown"]
    assert result["items"][0]["requests"] == 6
    assert result["geo"]["unavailable"] == 4
    assert result["geo"]["unknown"] == 2
    # Required mode fails before any write with the fixed code.
    db2 = tmp_path / "t5a_required.sqlite3"
    migrate(db2)
    with pytest.raises(GeoipError) as excinfo:
        run_import(
            db2,
            source=SourceConfig(
                source_id="t5a",
                format_id="nginx_combined",
                allowed_root=root,
                relative_path="t5a.log",
            ),
            site_id="default",
            site_name="T5a",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="t5a.log",
            hmac_key=HMAC_KEY,
            geoip_required=True,
        )
    assert str(excinfo.value) == "geoip_unavailable:database_required"
    with writer_transaction(db2) as conn:
        assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0


def test_corrupt_db_file_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    garbage = tmp_path / "garbage.mmdb"
    garbage.write_bytes(b"not a maxmind database")
    assert CountryLookup.open(garbage).available is False
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t5a.log").write_text("\n".join(LINES[:1]) + "\n", encoding="utf-8")
    db = tmp_path / "t5a_corrupt.sqlite3"
    migrate(db)
    with CountryLookup.open(garbage) as lookup:
        report = run_import(
            db,
            source=SourceConfig(
                source_id="t5a",
                format_id="nginx_combined",
                allowed_root=root,
                relative_path="t5a.log",
            ),
            site_id="default",
            site_name="T5a",
            site_hostname="example.org",
            server_type="nginx",
            path_alias="t5a.log",
            hmac_key=HMAC_KEY,
            country_lookup=lookup,
        )
    assert report.lines_accepted == 1
    assert report.geoip_available is False


def test_reprocess_enriches_stable_core_without_duplicates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t5a.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "t5a_reprocess.sqlite3"
    migrate(db)
    source = SourceConfig(
        source_id="t5a",
        format_id="nginx_combined",
        allowed_root=root,
        relative_path="t5a.log",
    )
    run_import(
        db,
        source=source,
        site_id="default",
        site_name="T5a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="t5a.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        before = conn.execute(
            "SELECT id, client_pseudonym, method, path, status, bytes FROM requests ORDER BY id"
        ).fetchall()
    assert len(before) == 6
    with _lookup() as lookup:
        first = run_reprocess(
            db,
            source=source,
            site_id="default",
            site_hostname="example.org",
            server_type="nginx",
            hmac_key=HMAC_KEY,
            country_lookup=lookup,
        )
    assert first.rows_verified == 6
    # Only the four database-read rows change (unavailable -> hit); the
    # two non-routable rows already stored the honest unknown outcome.
    assert first.rows_enriched == 4
    assert first.rows_mismatched == 0
    with writer_transaction(db) as conn:
        after = conn.execute(
            "SELECT id, client_pseudonym, method, path, status, bytes FROM requests ORDER BY id"
        ).fetchall()
        codes = conn.execute("SELECT country_code FROM requests ORDER BY ts_utc").fetchall()
    assert after == before
    assert [row[0] for row in codes] == ["US", "US", "AU", None, None, "US"]
    with _lookup() as lookup:
        second = run_reprocess(
            db,
            source=source,
            site_id="default",
            site_hostname="example.org",
            server_type="nginx",
            hmac_key=HMAC_KEY,
            country_lookup=lookup,
        )
    assert second.rows_verified == 6
    assert second.rows_enriched == 0


def test_country_without_configured_key_and_no_ip_egress(t5a):
    # Country derives from the transient validated address even when no
    # ORIGINAL_IP_KEY is configured (capture stays off); originals
    # never reach the API, exports, errors or model tools.
    client, token = t5a["client"], t5a["token"]
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "site_id": "default",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
    }
    for original in ("8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "203.0.113.5", "10.0.0.2"):
        assert original not in client.get("/api/v1/requests", params=params, headers=headers).text
        assert (
            original
            not in client.get(
                "/api/v1/exports/requests", params={**params, "format": "json"}, headers=headers
            ).text
        )
        assert original not in client.get("/api/v1/countries", params=params, headers=headers).text


def test_cli_geoip_source_precedence_and_env(tmp_path, monkeypatch):
    import argparse

    monkeypatch.chdir(tmp_path)
    garbage = tmp_path / "garbage.mmdb"
    garbage.write_bytes(b"not a maxmind database")
    monkeypatch.setenv("GEOIP_DB_PATH", str(garbage))
    args = argparse.Namespace(geoip_db=None)
    with db_cli._country_lookup(args) as lookup:
        assert lookup.available is False
    args = argparse.Namespace(geoip_db="/definitely/absent.mmdb")
    with db_cli._country_lookup(args) as lookup:
        assert lookup.available is False
    monkeypatch.setenv("GEOIP_DB_PATH", "")
    with db_cli._country_lookup(argparse.Namespace(geoip_db=None)) as lookup:
        assert lookup.available is False


def _web_login(t5a):
    client = t5a["client"]
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200, login.text[:300]
    return client


_WINDOW = (
    "site=default&range=custom&from=2026-10-27T00:00:00%2B00:00"
    "&to=2026-10-28T00:00:00%2B00:00&tz=UTC"
)


def test_country_pages_all_show_dbip_credit(t5a):
    client = _web_login(t5a)
    for path in (
        "/",
        "/requests",
        "/performance",
        "/seo",
        "/referrers",
        "/journeys",
        "/security",
        "/crawlers",
        "/errors",
        "/comparison",
    ):
        response = client.get(f"{path}?{_WINDOW}")
        assert response.status_code == 200, (path, response.text[:300])
        html = response.text
        # The shared filter-bar credit is the single plain-anchor
        # attribution on every country-filtered page.
        assert html.count('href="https://db-ip.com"') == 1, path
        assert "IP Geolocation by DB-IP" in html, path


def test_overview_country_chart_table_and_oob_country(t5a):
    client = _web_login(t5a)
    html = client.get(f"/?{_WINDOW}").text
    # Local Chart.js plot alongside the accessible country table.
    assert 'id="overview-countries-chart"' in html
    assert 'id="overview-countries-chart-data"' in html
    assert 'id="country-h"' in html
    assert "Lookup source:" in html
    assert "dbip-country-lite" in html and "2026-11" in html
    partial = client.get(f"/partials/overview?{_WINDOW}")
    assert partial.status_code == 200, partial.text[:300]
    # The country selector refreshes out-of-band with every Apply.
    assert 'id="f-country"' in partial.text
    assert 'hx-swap-oob="true"' in partial.text
    assert 'value="UNKNOWN"' in partial.text


def test_unknown_selection_copy_is_honest(t5a):
    client = _web_login(t5a)
    html = client.get(f"/?{_WINDOW}&country=UNKNOWN").text
    # An Unknown-only selection over a working database carries no
    # per-row source: the copy says exactly that instead of claiming
    # the server has no database configured.
    assert "carry no recorded country source" in html
    assert "No country database is configured" not in html
    assert "Coverage:" in html
    assert "legacy" in html


def test_unavailable_selection_copy_names_stored_rows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "t5a-unavailable-secret")
    monkeypatch.setenv("HMAC_KEY", "t5a-integration-hmac-key")
    root = tmp_path / "logs"
    root.mkdir()
    (root / "t5a.log").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    db = tmp_path / "t5a_unavailable.sqlite3"
    migrate(db)
    run_import(
        db,
        source=SourceConfig(
            source_id="t5a",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="t5a.log",
        ),
        site_id="default",
        site_name="T5a",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="t5a.log",
        hmac_key=HMAC_KEY,
    )
    with writer_transaction(db) as conn:
        create_admin_user(conn, username="admin", password_hash=hash_password("s3cret-pw"))
    from app.main import create_app

    client = TestClient(create_app(db_path=db, secure_cookies=False), raise_server_exceptions=False)
    assert (
        client.post(
            "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
        ).status_code
        == 200
    )
    html = client.get(f"/?{_WINDOW}").text
    # Rows stored while no database could be read say exactly that
    # (past storage fact with counts) — never a present-tense claim
    # about the configured server.
    assert "stored while no country database could be read" in html
    assert "No country database is configured" not in html


def test_export_envelope_and_csv_header_carry_geo_credit(t5a):
    import json as jsonlib

    client, token = t5a["client"], t5a["token"]
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "site_id": "default",
        "from": "2026-10-27T00:00:00+00:00",
        "to": "2026-10-28T00:00:00+00:00",
    }
    envelope = client.get(
        "/api/v1/exports/requests", params={**params, "export_format": "json"}, headers=headers
    )
    assert envelope.status_code == 200, envelope.text[:300]
    metadata = envelope.json()["metadata"]
    assert metadata["geo"]["with_country"] == 4
    assert metadata["geo"]["unknown"] == 2
    assert metadata["geo"]["sources"] == ["dbip-country-lite"]
    assert metadata["geo"]["releases"] == ["2026-11"]
    assert metadata["attribution"]["license"] == "CC BY 4.0"
    assert metadata["attribution"]["url"] == "https://db-ip.com"
    assert "8.8.8.8" not in envelope.text
    download = client.get(
        "/api/v1/exports/requests", params={**params, "export_format": "csv"}, headers=headers
    )
    assert download.status_code == 200, download.text[:300]
    geo_header = download.headers.get("X-Logcarve-Export-Geo", "")
    assert geo_header, "CSV download must carry the geo provenance header"
    assert geo_header.isascii()
    provenance = jsonlib.loads(geo_header)
    assert provenance["sources"] == ["dbip-country-lite"]
    assert provenance["releases"] == ["2026-11"]
    assert provenance["with_country"] == 4
    assert provenance["attribution"]["license"] == "CC BY 4.0"


def test_ai_get_report_countries_is_typed_bounded_and_linked(t5a):
    from app.ai import egress as egress_mod
    from app.ai.tools import definitions as tool_defs
    from app.web import evidence as evidence_mod

    assert "countries" in tool_defs.REPORT_NAMES
    db, rules = t5a["db"], t5a["rules"]
    with writer_transaction(db) as conn:
        envelope = tool_defs.execute_tool(
            conn,
            rules,
            name="get_report",
            arguments={
                "site_id": "default",
                "time_from": FROM.isoformat(),
                "time_to": TO.isoformat(),
                "report": "countries",
                "limit": 100,
                "offset": 0,
                "bucket": "day",
            },
            tool_call_id="tc-countries",
            observation_time=datetime(2026, 10, 28, tzinfo=UTC),
        )
    result = envelope["result"]
    by_country = {item["country"]: item for item in result["items"]}
    assert by_country["US"]["requests"] == 3
    assert by_country["AU"]["requests"] == 1
    assert by_country["Unknown"]["requests"] == 2
    assert result["geo"]["with_country"] == 4
    assert result["geo"]["sources"] == ["dbip-country-lite"]
    assert result["attribution"]["license"] == "CC BY 4.0"
    assert "8.8.8.8" not in str(result)
    # Hostile model narrowing cannot widen the trusted scope: an
    # unknown country fails closed at the typed contract.
    from app.db.database import connect

    hostile_conn = connect(db, read_only=True)
    try:
        with pytest.raises(tool_defs.ToolError):
            tool_defs.execute_tool(
                hostile_conn,
                rules,
                name="get_report",
                arguments={
                    "site_id": "default",
                    "time_from": FROM.isoformat(),
                    "time_to": TO.isoformat(),
                    "report": "countries",
                    "country": "XX1",
                    "limit": 100,
                    "offset": 0,
                    "bucket": "day",
                },
                tool_call_id="tc-hostile",
                observation_time=datetime(2026, 10, 28, tzinfo=UTC),
            )
    finally:
        hostile_conn.close()
    minimized = egress_mod.serialize_evidence("get_report", result)
    line = egress_mod.project_evidence_summary(
        tool_name="get_report",
        tool_call_id="tc-countries",
        minimized=minimized,
        filters=envelope["filters"],
        observation_time=envelope["observation_time"],
        coverage=envelope["coverage"],
        full_result=result,
        quality={"limitations": ["country-test"]},
    )
    assert len(line) <= 1600, len(line)
    assert '"countries":3' in line
    assert "IP Geolocation by DB-IP" in line
    # Evidence links to the actual Overview country section with the
    # same filters — never an invented page.
    href = evidence_mod.envelope_href("get_report", {**envelope["filters"], "country": "US"})
    assert href is not None and href.startswith("/?")
    assert "country=US" in href
    assert href.endswith("#country-h"), href


def test_ai_countries_report_scope_overrides_model_narrowing(t5a):
    from app.ai import service as ai_service

    scope_client = "a" * 64
    outcome = ai_service._execute_bounded_tool(
        t5a["db"],
        t5a["rules"],
        "get_report",
        {"report": "countries", "country": "AU", "client": "b" * 64},
        site_id="default",
        source_id=None,
        time_from=FROM,
        time_to=TO,
        country="US",
        client=scope_client,
        tool_index=0,
        investigation_id="t5a-scope-override",
        observation_time=datetime(2026, 10, 28, tzinfo=UTC),
    )
    # Trusted investigation scope wins over hostile model overrides.
    assert outcome["arguments"]["country"] == "US"
    assert outcome["arguments"]["client"] == scope_client
    assert outcome["envelope"]["filters"]["country"] == "US"
    assert len(outcome["history_line"]) <= 1600

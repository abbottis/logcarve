"""Parity T2b tests: journeys (E), expanded security (F), comparison (H).

Shared analytics layer only (HTTP wiring is T3, admin UI is T4).
Journeys are technical groupings by (HMAC pseudonym, sanitized
User-Agent) with a documented 30-minute inactivity split: they are
never visitors, people, browser sessions or clicks. Boundaries derive
from the authorized site/source event stream BEFORE content matchers,
so filters hide rows but never invent new starts. Window-edge
uncertainty is flagged, never resolved by reading outside the window.

All fixtures are synthetic with fixed timestamps (no wall-clock
dependence); the 120-row fixture, HMAC identity, auth/model ledger
and the 77-rule bot catalog are never modified here.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import queries, service
from app.analytics.contracts import (
    AnalyticsFilter,
    JourneyQuery,
    JourneyTimelineQuery,
    TimeWindow,
)
from app.analytics.rules import load_rules
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
SEC_RULES = load_rules(ROOT / "config" / "security_rules.yaml").rules
HMAC_KEY = b"parity-t2b-test-key"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)

SITE_J = "site-t2b-journey"
WINDOW_J = TimeWindow(
    time_from=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 13, 0, 0, tzinfo=UTC),
)

UA1 = "JourneyUA/1.0"
UA2 = "JourneyUA/2.0"
IP_A = "198.51.100.1"
IP_B = "203.0.113.9"
IP_C = "192.0.2.50"


def _line(ip: str, ts: str, path: str, status: int, ua: str, size: int = 100) -> str:
    return f'{ip} - - [{ts} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _journey_lines() -> bytes:
    rows = [
        # Client A / UA1: J1 = 10:00 + 29m59s + exactly 30m00s (same journey),
        # then a 30m01s gap starts J2; J2 holds two identical timestamps.
        (IP_A, "27/Oct/2026:10:00:00", "/entry-a", 200, UA1),
        (IP_A, "27/Oct/2026:10:29:59", "/a2", 200, UA1),
        (IP_A, "27/Oct/2026:10:59:59", "/a3", 404, UA1),
        (IP_A, "27/Oct/2026:11:30:00", "/a4", 200, UA1),
        (IP_A, "27/Oct/2026:11:30:00", "/a5", 200, UA1),
        # Same client, changed UA: a new grouping key, never a continuation.
        (IP_A, "27/Oct/2026:10:05:00", "/ua2-entry", 200, UA2),
        # Same UA, different HMAC client: separate journeys.
        (IP_B, "27/Oct/2026:10:00:30", "/entry-b", 200, UA1),
        (IP_B, "27/Oct/2026:10:10:00", "/b2", 404, UA1),
        # Late single-event journey, far from both window edges.
        (IP_C, "27/Oct/2026:12:00:00", "/late", 200, UA1),
    ]
    return ("\n".join(_line(*row) for row in rows) + "\n").encode()


def _import_journeys(tmp_path) -> Path:
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "j.log").write_bytes(_journey_lines())
    db = tmp_path / "t2b-j.sqlite3"
    migrate(db)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="t2b-j-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="j.log",
        ),
        site_id=SITE_J,
        site_name="T2b",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="j.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 9
    return db


def _journey_filt(**overrides) -> AnalyticsFilter:
    base: dict = {"site_id": SITE_J, "window": WINDOW_J}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _pseudo(ip: str) -> str:
    return pseudonymize_client(ip, HMAC_KEY)


def test_t2b_catalog_versions():
    """T2b pins: 77 bot rules, 11 security candidates (3 preserved v1)."""
    assert len(BOT_RULES) == 77
    assert len(SEC_RULES) == 11
    assert {r.id for r in SEC_RULES} >= {
        "sec-sensitive-path",
        "sec-repeated-client-errors",
        "sec-conflicting-bot-identity",
    }


def test_t2b_gap_boundary_exact_equality(tmp_path):
    """29m59s and exactly 30m00s continue; only >1800s splits."""
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.journeys(
            conn, JourneyQuery(filt=_journey_filt()), None, observation_time=NOW
        )
    finally:
        conn.close()
    assert result["total_groups"] == 5
    by_entry = {item["entry_path"]: item for item in result["items"]}
    assert set(by_entry) == {"/entry-a", "/a4", "/ua2-entry", "/entry-b", "/late"}
    first = by_entry["/entry-a"]
    assert (first["requests_total"], first["requests_shown"]) == (3, 3)
    assert (first["started_at"], first["ended_at"]) == (
        "2026-10-27T10:00:00+00:00",
        "2026-10-27T10:59:59+00:00",
    )
    assert first["duration_s"] == 3599
    second = by_entry["/a4"]
    assert (second["requests_total"], second["duration_s"]) == (2, 0)
    # Identical timestamps share one journey; UA change splits the key.
    assert by_entry["/ua2-entry"]["requests_total"] == 1
    assert by_entry["/entry-b"]["requests_total"] == 2
    assert first["journey_id"] != second["journey_id"] != by_entry["/ua2-entry"]["journey_id"]
    # Stable across repeated derivation.
    conn = connect(db, read_only=True)
    try:
        again = service.journeys(
            conn, JourneyQuery(filt=_journey_filt()), None, observation_time=NOW
        )
    finally:
        conn.close()
    assert {i["journey_id"] for i in again["items"]} == {i["journey_id"] for i in result["items"]}
    assert "strictly exceeds 1800 seconds" in result["gap_definition"]
    assert any("never visitors" in limit for limit in result["limitations"])


def test_t2b_filters_hide_but_never_invent_starts(tmp_path):
    """Status/path filters shrink shown counts; IDs, starts, entries stay."""
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        plain = service.journeys(conn, JourneyQuery(filt=_journey_filt()), None)
        narrowed = service.journeys(conn, JourneyQuery(filt=_journey_filt(status=200)), None)
        prefix = service.journeys(conn, JourneyQuery(filt=_journey_filt(path_prefix="/b2")), None)
    finally:
        conn.close()
    plain_ids = {i["entry_path"]: i["journey_id"] for i in plain["items"]}
    narrow_ids = {i["entry_path"]: i["journey_id"] for i in narrowed["items"]}
    # Same journeys, smaller shown counts: the 404s drop out.
    assert set(narrow_ids) == set(plain_ids)
    assert narrow_ids["/entry-a"] == plain_ids["/entry-a"]
    entry_a = next(i for i in narrowed["items"] if i["entry_path"] == "/entry-a")
    assert (entry_a["requests_total"], entry_a["requests_shown"]) == (3, 2)
    entry_b = next(i for i in narrowed["items"] if i["entry_path"] == "/entry-b")
    assert (entry_b["requests_total"], entry_b["requests_shown"]) == (2, 1)
    # A filter excluding the FIRST request cannot move the journey start
    # or its base-scope entry: one journey, starting at 10:00:30.
    assert prefix["total_groups"] == 1
    only = prefix["items"][0]
    assert only["journey_id"] == plain_ids["/entry-b"]
    assert only["started_at"] == "2026-10-27T10:00:30+00:00"
    assert only["entry_path"] == "/entry-b"
    assert (only["requests_total"], only["requests_shown"]) == (2, 1)


def test_t2b_window_edge_partial_flags_with_equality(tmp_path):
    """Edges are asymmetric: left is complete at exactly the gap, right stays partial.

    An excluded predecessor stands strictly before ``window_from``,
    so at exactly 1800s its gap would strictly exceed the limit and
    start its own journey (left complete). An unseen successor may
    sit exactly on the excluded ``window_to`` edge, where a gap of
    exactly 1800s still continues the journey (right partial).
    """
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        full = service.journeys(conn, JourneyQuery(filt=_journey_filt()), None)
        left = service.journeys(
            conn,
            JourneyQuery(
                filt=_journey_filt(
                    window=TimeWindow(
                        time_from=datetime(2026, 10, 27, 10, 15, 0, tzinfo=UTC),
                        time_to=datetime(2026, 10, 27, 13, 0, 0, tzinfo=UTC),
                    )
                )
            ),
            None,
        )
        right = service.journeys(
            conn,
            JourneyQuery(
                filt=_journey_filt(
                    window=TimeWindow(
                        time_from=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
                        time_to=datetime(2026, 10, 27, 11, 45, 0, tzinfo=UTC),
                    )
                )
            ),
            None,
        )
        exact = service.journeys(
            conn,
            JourneyQuery(
                filt=_journey_filt(
                    window=TimeWindow(
                        time_from=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
                        time_to=datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC),
                    )
                )
            ),
            None,
        )
    finally:
        conn.close()
    by_entry = {i["entry_path"]: i for i in full["items"]}
    assert by_entry["/entry-a"]["completeness"] == "partial-left"
    assert by_entry["/a4"]["completeness"] == "complete"
    assert by_entry["/late"]["completeness"] == "complete"
    # Narrowing the window re-derives from the smaller scope: the first
    # observed request (10:29:59, only 899s after the edge) is flagged.
    left_first = next(i for i in left["items"] if i["client_pseudonym"] == _pseudo(IP_A))
    assert left_first["entry_path"] == "/a2"
    assert left_first["started_at"] == "2026-10-27T10:29:59+00:00"
    assert left_first["left_truncated"] is True
    # A last journey ending 900s before the edge is right-partial,
    # and — unlike the left edge — exactly 1800s before the edge it
    # is still right-partial: an unseen request exactly on the
    # excluded edge would continue it (see the expanded-window
    # control in test_t2b_right_edge_equality_expanded_control).
    right_j2 = next(i for i in right["items"] if i["entry_path"] == "/a4")
    assert right_j2["right_truncated"] is True
    assert right_j2["completeness"] == "partial-right"
    exact_j2 = next(i for i in exact["items"] if i["entry_path"] == "/a4")
    assert exact_j2["right_truncated"] is True
    assert exact_j2["completeness"] == "partial-right"


def test_t2b_list_paging_sort_and_min_requests(tmp_path):
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        desc = service.journeys(
            conn, JourneyQuery(filt=_journey_filt(), sort="requests_desc"), None
        )
        assert [i["entry_path"] for i in desc["items"]] == [
            "/entry-a",
            "/entry-b",
            "/a4",
            "/ua2-entry",
            "/late",
        ]
        asc = service.journeys(conn, JourneyQuery(filt=_journey_filt(), sort="start_asc"), None)
        assert [i["entry_path"] for i in asc["items"]] == [
            "/entry-a",
            "/entry-b",
            "/ua2-entry",
            "/a4",
            "/late",
        ]
        rdesc = service.journeys(conn, JourneyQuery(filt=_journey_filt(), sort="start_desc"), None)
        assert [i["entry_path"] for i in rdesc["items"]] == [
            "/late",
            "/a4",
            "/ua2-entry",
            "/entry-b",
            "/entry-a",
        ]
        dur = service.journeys(conn, JourneyQuery(filt=_journey_filt(), sort="duration_desc"), None)
        assert [i["entry_path"] for i in dur["items"]] == [
            "/entry-a",
            "/entry-b",
            "/ua2-entry",
            "/a4",
            "/late",
        ]
        page = service.journeys(
            conn,
            JourneyQuery(filt=_journey_filt(limit=2, offset=1), sort="requests_desc"),
            None,
        )
        assert page["total_groups"] == 5
        assert [i["entry_path"] for i in page["items"]] == ["/entry-b", "/a4"]
        few = service.journeys(conn, JourneyQuery(filt=_journey_filt(), min_requests=2), None)
        assert few["total_groups"] == 3
        assert {i["entry_path"] for i in few["items"]} == {
            "/entry-a",
            "/a4",
            "/entry-b",
        }
        with pytest.raises(ValueError):
            queries.journey_list(
                conn,
                JourneyQuery(filt=_journey_filt(), sort="nope"),  # type: ignore[arg-type]
                None,
            )
    finally:
        conn.close()


def test_t2b_timeline_bounded_and_filter_stable(tmp_path):
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        listed = service.journeys(conn, JourneyQuery(filt=_journey_filt()), None)
        first = next(i for i in listed["items"] if i["entry_path"] == "/entry-a")
        key = {
            "client_pseudonym": first["client_pseudonym"],
            "user_agent": UA1,
            "journey_start": datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
        }
        full = service.journey_timeline(
            conn, JourneyTimelineQuery(filt=_journey_filt(), **key), None
        )
        assert full["journey_id"] == first["journey_id"]
        assert full["requests_total"] == 3 and full["requests_shown"] == 3
        assert [row["path"] for row in full["items"]] == ["/entry-a", "/a2", "/a3"]
        assert full["truncated"] is False
        page = service.journey_timeline(
            conn,
            JourneyTimelineQuery(filt=_journey_filt(limit=2), **key),
            None,
        )
        assert (page["shown"], page["total"], page["truncated"]) == (2, 3, True)
        rest = service.journey_timeline(
            conn,
            JourneyTimelineQuery(filt=_journey_filt(limit=2, offset=2), **key),
            None,
        )
        assert [row["path"] for row in rest["items"]] == ["/a3"]
        # The identical-timestamp pair keeps insertion (id) order.
        pair = service.journey_timeline(
            conn,
            JourneyTimelineQuery(
                filt=_journey_filt(),
                client_pseudonym=_pseudo(IP_A),
                user_agent=UA1,
                journey_start=datetime(2026, 10, 27, 11, 30, 0, tzinfo=UTC),
            ),
            None,
        )
        assert [row["path"] for row in pair["items"]] == ["/a4", "/a5"]
        # Filters shrink the timeline but keep the journey identity.
        filtered = service.journey_timeline(
            conn,
            JourneyTimelineQuery(filt=_journey_filt(status=200), **key),
            None,
        )
        assert filtered["journey_id"] == first["journey_id"]
        assert (filtered["requests_shown"], filtered["requests_total"]) == (2, 3)
        assert [row["path"] for row in filtered["items"]] == ["/entry-a", "/a2"]
        with pytest.raises(KeyError):
            service.journey_timeline(
                conn,
                JourneyTimelineQuery(
                    filt=_journey_filt(),
                    client_pseudonym=_pseudo(IP_A),
                    user_agent=UA1,
                    journey_start=datetime(2026, 10, 27, 10, 1, 0, tzinfo=UTC),
                ),
                None,
            )
        with pytest.raises(ValueError):
            JourneyTimelineQuery(
                filt=_journey_filt(),
                client_pseudonym="x",
                journey_start=datetime(2026, 10, 27, 10, 0, 0),
            )
    finally:
        conn.close()


def test_t2b_entry_paths_match_list_grouping(tmp_path):
    db = _import_journeys(tmp_path)
    conn = connect(db, read_only=True)
    try:
        entries = service.journey_entry_paths(conn, _journey_filt(), None)
        listed = service.journeys(conn, JourneyQuery(filt=_journey_filt()), None)
    finally:
        conn.close()
    assert entries["total_groups"] == 5
    by_entry = {row["entry_path"]: row for row in entries["items"]}
    assert sum(row["journeys"] for row in entries["items"]) == listed["total_groups"]
    assert by_entry["/entry-a"]["journeys"] == 1
    assert by_entry["/entry-a"]["partial_journeys"] == 1
    assert by_entry["/a4"]["complete_journeys"] == 1
    assert entries["total_groups"] == len(entries["items"])
    assert "outside the window" in entries["partial_caveat"]
    # min_requests agrees with the list: only multi-request journeys qualify.
    conn = connect(db, read_only=True)
    try:
        narrow = service.journey_entry_paths(conn, _journey_filt(), None, min_requests=2)
    finally:
        conn.close()
    assert narrow["total_groups"] == 3
    assert {row["entry_path"] for row in narrow["items"]} == {
        "/entry-a",
        "/a4",
        "/entry-b",
    }


SITE_S = "site-t2b-sec"
WINDOW_S = TimeWindow(
    time_from=datetime(2026, 10, 28, 10, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 28, 11, 0, 0, tzinfo=UTC),
)

SWEEP_UA = "Sweep/1.0"
CONFLICT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) GPTBot/1.1"

RARE_SWEEP = 5050


def _sec_lines() -> bytes:
    out: list[str] = []

    def add(ip: str, ts: str, path: str, status: int, ua: str) -> None:
        out.append(_line(ip, ts, path, status, ua))

    # Sweep client: 3 sensitive hits plus 5050 distinct rare CMS paths.
    add("198.51.100.21", "28/Oct/2026:10:00:00", "/.env", 404, SWEEP_UA)
    add("198.51.100.21", "28/Oct/2026:10:00:01", "/.env", 404, SWEEP_UA)
    add("198.51.100.21", "28/Oct/2026:10:00:02", "/.env", 404, SWEEP_UA)
    for i in range(RARE_SWEEP):
        second = 60 + i // 2
        add(
            "198.51.100.21",
            f"28/Oct/2026:10:{second // 60:02d}:{second % 60:02d}",
            f"/wp-content/rare-{i:04d}",
            404,
            SWEEP_UA,
        )
    add("198.51.100.22", "28/Oct/2026:10:50:00", "/wp-login/rare-end", 404, SWEEP_UA)
    # 401/403 cluster: one repeat offender plus two benign controls.
    for second in range(6):
        add("198.51.100.31", f"28/Oct/2026:10:05:{second:02d}", "/login", 401, "AuthTest/1.0")
    add("198.51.100.31", "28/Oct/2026:10:06:00", "/admin", 403, "AuthTest/1.0")
    add("198.51.100.31", "28/Oct/2026:10:06:01", "/admin", 403, "AuthTest/1.0")
    add("198.51.100.32", "28/Oct/2026:10:07:00", "/login", 401, "AuthTest/1.0")
    for second in range(4):
        add(
            "198.51.100.33",
            f"28/Oct/2026:10:08:{second:02d}",
            "/admin",
            403,
            "AuthTest/1.0",
        )
    # Breadth: four distinct sensitive paths fire; three stay silent.
    for path in ["/.env", "/.git/config", "/wp-admin/", "/xmlrpc.php"]:
        add("198.51.100.34", "28/Oct/2026:10:20:00", path, 200, "ProbeTest/1.0")
    for path in ["/.env", "/.git/config", "/wp-admin/"]:
        add("198.51.100.35", "28/Oct/2026:10:21:00", path, 200, "ProbeTest/1.0")
    # Traversal spellings plus a single-dot control that must not match.
    add("198.51.100.41", "28/Oct/2026:10:30:00", "/a/../b", 404, "TraversalTest/1.0")
    add("198.51.100.41", "28/Oct/2026:10:30:01", "/a/%2e%2e/b", 404, "TraversalTest/1.0")
    add("198.51.100.41", "28/Oct/2026:10:30:02", "/a/%252e%252e/b", 404, "TraversalTest/1.0")
    add("198.51.100.41", "28/Oct/2026:10:30:03", "/a/%c0%af/b", 404, "TraversalTest/1.0")
    add("198.51.100.41", "28/Oct/2026:10:30:04", "/A/%2E%2E/B", 200, "TraversalTest/1.0")
    add("198.51.100.42", "28/Oct/2026:10:31:00", "/x/%2e", 200, "TraversalTest/1.0")
    # Origin-observed malformed requests (events) ...
    add("198.51.100.43", "28/Oct/2026:10:40:00", "/bad", 400, "BadTest/1.0")
    add("198.51.100.43", "28/Oct/2026:10:40:01", "/bad", 400, "BadTest/1.0")
    # ... versus parser-rejected lines (never events).
    out.append("this is not a log line")
    out.append("neither is this")
    # Config / CMS / device singletons and a conflicting identity.
    add("198.51.100.44", "28/Oct/2026:10:45:00", "/wp-config.php", 200, "ConfigTest/1.0")
    add("198.51.100.44", "28/Oct/2026:10:45:01", "/server-status", 200, "ConfigTest/1.0")
    add("198.51.100.44", "28/Oct/2026:10:45:02", "/administrator/", 404, "ConfigTest/1.0")
    add("198.51.100.44", "28/Oct/2026:10:45:03", "/cgi-bin/test.cgi", 404, "ConfigTest/1.0")
    add("198.51.100.45", "28/Oct/2026:10:55:00", "/", 200, CONFLICT_UA)
    add("198.51.100.46", "28/Oct/2026:10:56:00", "/", 200, "Normal/1.0")
    add("198.51.100.46", "28/Oct/2026:10:56:01", "/", 200, "Normal/1.0")
    add("198.51.100.46", "28/Oct/2026:10:56:02", "/", 200, "Normal/1.0")
    return ("\n".join(out) + "\n").encode()


def _import_sec(tmp_path) -> tuple[Path, object]:
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "s.log").write_bytes(_sec_lines())
    db = tmp_path / "t2b-s.sqlite3"
    migrate(db)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="t2b-s-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="s.log",
        ),
        site_id=SITE_S,
        site_name="T2b",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="s.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed"
    assert imported.lines_rejected == 2
    assert imported.records_inserted == 5090
    return db, imported


def _sec_filt(**overrides) -> AnalyticsFilter:
    base: dict = {"site_id": SITE_S, "window": WINDOW_S}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _findings_by_rule(tmp_path):
    db, _ = _import_sec(tmp_path)
    conn = connect(db, read_only=True)
    try:
        findings = service.security_findings(conn, _sec_filt(), SEC_RULES, observation_time=NOW)
    finally:
        conn.close()
    by_rule: dict[str, list] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)
    return findings, by_rule


def test_t2b_sensitive_path_exact_and_legacy_shape(tmp_path):
    _, by_rule = _findings_by_rule(tmp_path)
    sensitive = by_rule["sec-sensitive-path"]
    assert len(sensitive) == 1
    assert sensitive[0].counts == {"requests": 10, "distinct_paths": 4}
    assert sensitive[0].rule_version == 1
    assert sensitive[0].observation_time == NOW.isoformat()


def test_t2b_exact_totals_beyond_old_distinct_cap(tmp_path):
    """5050 rare CMS paths: totals stay exact, samples stay bounded."""
    _, by_rule = _findings_by_rule(tmp_path)
    cms = by_rule["sec-cms-probe"]
    assert len(cms) == 1
    assert cms[0].counts == {"requests": 5052, "distinct_paths": 5052}
    evidence = cms[0].evidence
    assert evidence["paths_total"] == 5052
    assert evidence["paths_shown"] == 20
    assert evidence["paths_truncated"] is True
    # The alphabetically last rare path is counted but not sampled:
    # totals never derive from the sample.
    assert "/wp-content/rare-5049" not in {row["path"] for row in evidence["paths"]}
    assert evidence["paths"][0]["path"] == "/administrator/"
    # The sweep client is one exact legacy offender, all-status sample.
    repeated = by_rule["sec-repeated-client-errors"]
    offenders = {f.evidence["client_pseudonym"]: f for f in repeated}
    assert set(offenders) == {_pseudo("198.51.100.21"), _pseudo("198.51.100.31")}
    sweep = offenders[_pseudo("198.51.100.21")]
    assert sweep.counts == {"errors": 5053, "distinct_paths": 5051}
    assert sweep.evidence["sample_paths_shown"] == 5
    assert sweep.evidence["sample_paths_total"] == 5051
    assert sweep.evidence["offenders_truncated"] is False
    assert sweep.evidence["sample_paths"][0] == {
        "path": "/.env",
        "status": 404,
        "hits": 3,
    }


def test_t2b_401_403_rate_with_benign_controls(tmp_path):
    _, by_rule = _findings_by_rule(tmp_path)
    cluster = by_rule["sec-auth-challenge-cluster"]
    assert len(cluster) == 1
    assert cluster[0].counts == {"requests": 13, "distinct_paths": 2}
    assert "challenge" in cluster[0].meaning
    assert "failed login" in cluster[0].meaning
    assert cluster[0].evidence["paths_total"] == 2
    assert {
        (row["path"], row["status"], row["requests"]) for row in cluster[0].evidence["paths"]
    } == {("/login", 401, 7), ("/admin", 403, 6)}
    rate = by_rule["sec-repeated-auth-challenges"]
    assert len(rate) == 1
    assert rate[0].evidence["client_pseudonym"] == _pseudo("198.51.100.31")
    assert rate[0].counts == {"requests": 8, "distinct_paths": 2}
    assert rate[0].evidence["sample_paths_total"] == 2
    # Benign single/few-challenge clients are never flagged.
    flagged = {f.evidence["client_pseudonym"] for f in rate}
    assert _pseudo("198.51.100.32") not in flagged
    assert _pseudo("198.51.100.33") not in flagged


def test_t2b_probe_breadth_threshold(tmp_path):
    _, by_rule = _findings_by_rule(tmp_path)
    breadth = by_rule["sec-probe-breadth"]
    flagged = {f.evidence["client_pseudonym"] for f in breadth}
    # The sweep client (5050 distinct sensitive paths), the 4-path probe
    # and the 4-path config/CMS/device sweep all qualify; narrower
    # clients stay silent.
    assert flagged == {
        _pseudo("198.51.100.21"),
        _pseudo("198.51.100.34"),
        _pseudo("198.51.100.44"),
    }
    four = next(f for f in breadth if f.evidence["client_pseudonym"] == _pseudo("198.51.100.34"))
    assert four.counts == {"requests": 4, "distinct_paths": 4}
    sweep = next(f for f in breadth if f.evidence["client_pseudonym"] == _pseudo("198.51.100.21"))
    assert sweep.counts == {"requests": 5053, "distinct_paths": 5051}
    assert _pseudo("198.51.100.35") not in flagged


def test_t2b_traversal_spellings_bounded_no_decoding(tmp_path):
    """Literal, single-, double-encoded and overlong spellings match as
    stored; nothing is percent-decoded at ingest or match time."""
    _, by_rule = _findings_by_rule(tmp_path)
    traversal = by_rule["sec-traversal-attempt"]
    assert len(traversal) == 1
    assert traversal[0].counts == {"requests": 5, "distinct_paths": 5}
    assert "never a decoded path" in traversal[0].meaning
    stored = {row["path"] for row in traversal[0].evidence["paths"]}
    assert stored == {
        "/a/../b",
        "/a/%2e%2e/b",
        "/a/%252e%252e/b",
        "/a/%c0%af/b",
        "/A/%2E%2E/B",
    }
    # The mixed-case spelling matches case-insensitively yet the stored
    # bytes keep their case; the single-dot spelling never matches.
    assert "/x/%2e" not in stored


def test_t2b_malformed_line_vs_origin_event(tmp_path):
    db, _ = _import_sec(tmp_path)
    conn = connect(db, read_only=True)
    try:
        lines = service.rejected_lines(conn, _sec_filt(), SEC_RULES, observation_time=NOW)
        findings = service.security_findings(conn, _sec_filt(), SEC_RULES, observation_time=NOW)
    finally:
        conn.close()
    assert lines["line_totals"] == {
        "lines_total": 5092,
        "lines_accepted": 5090,
        "lines_rejected": 2,
        "records_replayed": 0,
    }
    assert "malformed_line" in lines["reason_codes"]
    assert "never described as persisted events" in lines["line_vs_event"]
    bad = next(f for f in findings if f.rule_id == "sec-origin-bad-request")
    assert bad.counts == {"requests": 2, "distinct_paths": 1}
    assert bad.evidence["paths_total"] == 1
    # Rejected lines are line-level only: no finding carries them.
    for finding in findings:
        for row in finding.evidence.get("paths", []):
            assert "not a log line" not in row["path"]


def test_t2b_config_cms_device_and_conflict_preserved(tmp_path):
    _, by_rule = _findings_by_rule(tmp_path)
    assert by_rule["sec-exposed-config"][0].counts == {"requests": 2, "distinct_paths": 2}
    assert by_rule["sec-device-proxy"][0].counts == {"requests": 1, "distinct_paths": 1}
    conflict = by_rule["sec-conflicting-bot-identity"]
    assert len(conflict) == 1
    assert conflict[0].rule_version == 1
    assert conflict[0].counts == {"requests": 1, "distinct_agents": 1}
    assert conflict[0].evidence["agents_total"] == 1
    # Fourteen findings in all: the three preserved plus eleven T2b
    # originals (legacy errors contributes two offender findings and
    # breadth three).
    findings_count = sum(len(items) for items in by_rule.values())
    assert findings_count == 14
    assert set(by_rule) == {
        "sec-sensitive-path",
        "sec-repeated-client-errors",
        "sec-conflicting-bot-identity",
        "sec-exposed-config",
        "sec-cms-probe",
        "sec-device-proxy",
        "sec-traversal-attempt",
        "sec-origin-bad-request",
        "sec-auth-challenge-cluster",
        "sec-repeated-auth-challenges",
        "sec-probe-breadth",
    }
    for items in by_rule.values():
        for finding in items:
            assert finding.severity == "candidate"
            assert finding.observation_time == NOW.isoformat()
            assert finding.coverage_summary["unique_events"] == 5090
            assert any("investigation candidate" in limit for limit in finding.limitations)


SITE_C = "site-t2b-compare"
WIN_PREV = TimeWindow(
    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
)
WIN_CUR = TimeWindow(
    time_from=datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 11, 0, 0, tzinfo=UTC),
)

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
GPT_UA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1"
CURL_UA = "curl/8.5.0"


def _compare_lines() -> bytes:
    out: list[str] = []

    def add(ip: str, ts: str, path: str, status: int, size: int, ua: str) -> None:
        out.append(f'{ip} - - [{ts} +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"')

    # Previous hour: 8 requests, 650 bytes, 1 error, 2 bots, 1 automation.
    for minute in range(4):
        add("198.51.100.1", f"27/Oct/2026:09:{minute:02d}:00", "/", 200, 100, BROWSER_UA)
    add("198.51.100.2", "27/Oct/2026:09:10:00", "/old", 404, 50, BROWSER_UA)
    add("198.51.100.3", "27/Oct/2026:09:20:00", "/bot", 200, 60, GPT_UA)
    add("198.51.100.3", "27/Oct/2026:09:21:00", "/bot", 200, 60, GPT_UA)
    add("198.51.100.4", "27/Oct/2026:09:30:00", "/tool", 200, 80, CURL_UA)
    # Current hour: 15 requests, 1210 bytes, 2x4xx, 1x5xx, 4 bots.
    for minute in range(8):
        add("198.51.100.1", f"27/Oct/2026:10:{minute:02d}:00", "/", 200, 100, BROWSER_UA)
    add("198.51.100.2", "27/Oct/2026:10:10:00", "/old", 404, 50, BROWSER_UA)
    add("198.51.100.2", "27/Oct/2026:10:11:00", "/old", 404, 50, BROWSER_UA)
    add("198.51.100.2", "27/Oct/2026:10:12:00", "/new", 500, 70, BROWSER_UA)
    for minute in range(20, 24):
        add("198.51.100.3", f"27/Oct/2026:10:{minute:02d}:00", "/bot", 200, 60, GPT_UA)
    return ("\n".join(out) + "\n").encode()


def _import_compare(tmp_path) -> Path:
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "c.log").write_bytes(_compare_lines())
    db = tmp_path / "t2b-c.sqlite3"
    migrate(db)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="t2b-c-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="c.log",
        ),
        site_id=SITE_C,
        site_name="T2b",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="c.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed" and imported.records_inserted == 23
    return db


def _cmp_filt(window: TimeWindow, **overrides) -> AnalyticsFilter:
    base: dict = {"site_id": SITE_C, "window": window}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _metric(result: dict, name: str) -> dict:
    return next(m for m in result["metrics"] if m["name"] == name)  # type: ignore[union-attr]


def test_t2b_compare_equal_windows_exact_deltas(tmp_path):
    db = _import_compare(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(
            conn,
            _cmp_filt(WIN_CUR),
            _cmp_filt(WIN_PREV),
            BOT_RULES,
            observation_time=NOW,
        )
    finally:
        conn.close()
    assert result["window_seconds"] == 3600
    assert result["generated_at"] == NOW.isoformat()
    requests = _metric(result, "requests")
    assert (requests["current"], requests["previous"]) == (15, 8)
    assert requests["absolute_change"] == 7
    assert requests["ratio"] == 15 / 8
    assert requests["percent"] == (15 / 8 - 1) * 100
    assert requests["ratio_status"] == "ok"
    assert _metric(result, "errors_4xx")["ratio"] == 2.0
    assert _metric(result, "errors_5xx")["ratio_status"] == "zero_baseline"
    assert _metric(result, "errors_5xx")["ratio"] is None
    assert _metric(result, "errors_5xx")["absolute_change"] == 1
    assert _metric(result, "bytes_total")["current"] == 1210
    assert _metric(result, "bytes_total")["previous"] == 650
    assert _metric(result, "claimed_bot_requests")["ratio"] == 2.0
    automation = _metric(result, "automation_requests")
    assert (automation["current"], automation["previous"]) == (0, 1)
    assert automation["ratio"] == 0.0
    rate = _metric(result, "requests_per_hour")
    assert (rate["current"], rate["previous"]) == (15.0, 8.0)
    assert rate["ratio"] == 15 / 8
    # Both coverage ranges travel with the comparison.
    assert result["coverage"]["current"]["unique_events"] == 15
    assert result["coverage"]["previous"]["unique_events"] == 8
    assert result["coverage"]["current"]["observed_min"] == "2026-10-27T10:00:00+00:00"
    assert result["coverage"]["current"]["observed_max"] == "2026-10-27T10:23:00+00:00"
    assert result["coverage"]["previous"]["observed_min"] == "2026-10-27T09:00:00+00:00"
    assert result["comparable"] is True
    assert "no hidden widening" in " ".join(str(limit) for limit in result["limitations"])


def test_t2b_compare_previous_window_filter(tmp_path):
    """The previous-window helper slides exactly one duration, same scope."""
    current = _cmp_filt(WIN_CUR, status=404)
    previous = service.previous_window_filter(current)
    assert previous.window.time_from == WIN_PREV.time_from
    assert previous.window.time_to == WIN_PREV.time_to
    assert previous.site_id == current.site_id
    assert previous.status == 404
    db = _import_compare(tmp_path)
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(conn, current, previous, BOT_RULES)
    finally:
        conn.close()
    assert _metric(result, "errors_4xx")["current"] == 2
    assert _metric(result, "errors_4xx")["previous"] == 1


def test_t2b_compare_zero_and_empty_baseline(tmp_path):
    db = _import_compare(tmp_path)
    conn = connect(db, read_only=True)
    try:
        empty = service.compare_windows(
            conn,
            _cmp_filt(WIN_CUR),
            _cmp_filt(
                TimeWindow(
                    time_from=datetime(2026, 10, 27, 8, 0, 0, tzinfo=UTC),
                    time_to=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
                )
            ),
            BOT_RULES,
        )
    finally:
        conn.close()
    requests = _metric(empty, "requests")
    assert (requests["current"], requests["previous"]) == (15, 0)
    assert requests["absolute_change"] == 15
    assert requests["ratio"] is None
    assert requests["ratio_status"] == "zero_baseline"
    assert requests["percent"] is None
    assert empty["comparable"] is False
    assert any("baseline" in reason for reason in empty["comparable_reasons"])
    assert empty["coverage"]["previous"]["unique_events"] == 0


def test_t2b_compare_rejects_unequal_scope(tmp_path):
    db = _import_compare(tmp_path)
    conn = connect(db, read_only=True)
    try:
        with pytest.raises(ValueError):
            service.compare_windows(
                conn,
                _cmp_filt(WIN_CUR),
                _cmp_filt(
                    TimeWindow(
                        time_from=datetime(2026, 10, 27, 8, 0, 0, tzinfo=UTC),
                        time_to=datetime(2026, 10, 27, 9, 30, 0, tzinfo=UTC),
                    )
                ),
                BOT_RULES,
            )
        with pytest.raises(ValueError):
            service.compare_windows(
                conn,
                _cmp_filt(WIN_CUR),
                AnalyticsFilter(
                    site_id="other-site",
                    window=WIN_PREV,
                ),
                BOT_RULES,
            )
        with pytest.raises(ValueError):
            service.compare_windows(
                conn,
                _cmp_filt(WIN_CUR),
                _cmp_filt(WIN_PREV, source_id="other-source"),
                BOT_RULES,
            )
    finally:
        conn.close()


def test_t2b_compare_insufficient_coverage(tmp_path):
    """A failed import on either side marks every ratio unavailable."""
    db = _import_compare(tmp_path)
    holder = connect(db)
    try:
        holder.execute("UPDATE imports SET status = 'failed'")
        holder.commit()
    finally:
        holder.close()
    conn = connect(db, read_only=True)
    try:
        result = service.compare_windows(conn, _cmp_filt(WIN_CUR), _cmp_filt(WIN_PREV), BOT_RULES)
    finally:
        conn.close()
    assert result["comparable"] is False
    for metric in result["metrics"]:
        assert metric["ratio"] is None
        assert metric["ratio_status"] == "insufficient_coverage"
        # Absolute changes stay exact over the observed rows.
        assert metric["absolute_change"] == metric["current"] - metric["previous"]
    assert any("coverage limited" in reason for reason in result["comparable_reasons"])

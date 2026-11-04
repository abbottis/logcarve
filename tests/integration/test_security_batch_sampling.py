"""Batched per-client path sampling: hand-counted equivalence and scope tests.

Synthetic Combined lines only (TEST-NET addresses, no real logs). Every
expected sample below was derived by hand from the listed lines, not from
the implementation. The batched helper must return exactly what the
single-client helper returns, with every base filter applied BEFORE
grouping and all-status sampling preserved.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.analytics import queries, service
from app.analytics.classification import build_classifier
from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.analytics.rules import load_rules
from app.db.database import connect
from app.db.importer import run_import
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

ROOT = Path(__file__).resolve().parent.parent.parent
HMAC_KEY = b"synthetic-test-hmac-key"
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules
SEC_RULES = load_rules(ROOT / "config" / "security_rules.yaml").rules

WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 27, 11, 0, 0, tzinfo=UTC),
)
WIDE_WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 29, 0, 0, 0, tzinfo=UTC),
)
EMPTY_WINDOW = TimeWindow(
    time_from=datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC),
    time_to=datetime(2026, 10, 28, 13, 0, 0, tzinfo=UTC),
)


def _line(host, stamp, method, path, status, size=10, ua="test/1.0"):
    return f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def _p(host):
    return pseudonymize_client(host, HMAC_KEY)


def _main_lines():
    lines = []
    # Tie client .60: /a404x3 + /a200x1, /b404x3, /c500x2 -> 4xx errors 6.
    for minute in (0, 1, 2):
        lines.append(
            _line("203.0.113.60", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/b", 404)
        )
    for minute in (3, 4, 5):
        lines.append(
            _line("203.0.113.60", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/a", 404)
        )
    for minute in (6, 7):
        lines.append(
            _line("203.0.113.60", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/c", 500)
        )
    lines.append(_line("203.0.113.60", "27/Oct/2026:10:08:00 +0100", "GET", "/a", 200))
    # Cap client .61: /p1 200x3 + /p1..p7 404x1 -> 4xx errors 7.
    for minute in (10, 11, 12):
        lines.append(
            _line("203.0.113.61", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/p1", 200)
        )
    for index in range(7):
        lines.append(
            _line(
                "203.0.113.61",
                f"27/Oct/2026:10:{13 + index:02d}:00 +0100",
                "GET",
                f"/p{index + 1}",
                404,
            )
        )
    # Filter client .62: /f1 404x5 + /f2 200x3 -> 4xx errors 5.
    for minute in range(20, 25):
        lines.append(
            _line("203.0.113.62", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/f1", 404)
        )
    for minute in range(25, 28):
        lines.append(
            _line("203.0.113.62", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/f2", 200)
        )
    # Window client .63: /w1 404x5 in-window, /w2 404x4 out-of-window.
    for minute in range(30, 35):
        lines.append(
            _line("203.0.113.63", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/w1", 404)
        )
    for minute in range(40, 44):
        lines.append(
            _line("203.0.113.63", f"28/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/w2", 404)
        )
    # Cross-source client .65: /q1 404x3 here, /q2 404x3 in second source.
    for minute in range(55, 58):
        lines.append(
            _line("203.0.113.65", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/q1", 404)
        )
    # Bot clients: Googlebot .66 (/g1 404x5), plain Mozilla .67 (/m1 404x5).
    for minute in range(40, 45):
        lines.append(
            _line(
                "203.0.113.66",
                f"27/Oct/2026:10:{minute:02d}:00 +0100",
                "GET",
                "/g1",
                404,
                ua="Googlebot/2.1",
            )
        )
    for minute in range(45, 50):
        lines.append(
            _line(
                "203.0.113.67",
                f"27/Oct/2026:10:{minute:02d}:00 +0100",
                "GET",
                "/m1",
                404,
                ua="Mozilla/5.0",
            )
        )
    return lines


def _second_source_lines():
    return [
        _line("203.0.113.65", f"27/Oct/2026:10:{minute:02d}:00 +0100", "GET", "/q2", 404)
        for minute in range(52, 55)
    ]


def _other_site_lines():
    return [
        _line("203.0.113.64", f"27/Oct/2026:10:{50 + minute:02d}:00 +0100", "GET", "/s1", 404)
        for minute in range(5)
    ]


def _import(db, name, site, lines):
    root = db.parent / f"logs_{name}"
    root.mkdir(exist_ok=True)
    (root / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    run_import(
        db,
        source=SourceConfig(
            source_id=f"{name}-combined",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id=site,
        site_name=f"{site} site",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=HMAC_KEY,
    )


@pytest.fixture
def sampling_db(tmp_path):
    db = tmp_path / "sampling.sqlite3"
    _import(db, "example", "default", _main_lines())
    _import(db, "second", "default", _second_source_lines())
    _import(db, "other", "other", _other_site_lines())
    return db


@pytest.fixture
def cap_db(tmp_path):
    db = tmp_path / "cap.sqlite3"
    lines = []
    for client in range(101):
        host = f"198.51.100.{client + 1}"
        for path in range(5):
            lines.append(
                _line(host, f"27/Oct/2026:10:{path:02d}:00 +0100", "GET", f"/c{client}p{path}", 404)
            )
    _import(db, "example", "default", lines)
    return db


def _filt(**overrides):
    base = {"site_id": "default", "window": WINDOW}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _clf():
    return build_classifier(list(BOT_RULES))


def test_batched_matches_single_client_for_every_candidate(sampling_db):
    filt = _filt()
    conn = connect(sampling_db, read_only=True)
    try:
        candidates = queries.repeated_client_errors(conn, filt, min_errors=5)
        assert {c["client_pseudonym"] for c in candidates} == {
            _p("203.0.113.60"),
            _p("203.0.113.61"),
            _p("203.0.113.62"),
            _p("203.0.113.63"),
            _p("203.0.113.65"),
            _p("203.0.113.66"),
            _p("203.0.113.67"),
        }
        batched = queries.sample_paths_for_clients(
            conn, filt, [c["client_pseudonym"] for c in candidates]
        )
        for candidate in candidates:
            expected = queries.sample_paths_for_client(
                conn, filt, client_pseudonym=str(candidate["client_pseudonym"])
            )
            assert batched[str(candidate["client_pseudonym"])] == expected
        # Deterministic across calls.
        again = queries.sample_paths_for_clients(
            conn, filt, [c["client_pseudonym"] for c in candidates]
        )
        assert again == batched
    finally:
        conn.close()


def test_tie_order_and_all_status_semantics(sampling_db):
    conn = connect(sampling_db, read_only=True)
    try:
        batched = queries.sample_paths_for_clients(conn, _filt(), [_p("203.0.113.60")])
        # 3-3 tie breaks by path; 500/200 rows stay sampled (all-status).
        assert batched[_p("203.0.113.60")] == [
            {"path": "/a", "status": 404, "hits": 3},
            {"path": "/b", "status": 404, "hits": 3},
            {"path": "/c", "status": 500, "hits": 2},
            {"path": "/a", "status": 200, "hits": 1},
        ]
        base = queries.sample_paths_for_clients(conn, _filt(), [_p("203.0.113.62")])
        assert base[_p("203.0.113.62")] == [
            {"path": "/f1", "status": 404, "hits": 5},
            {"path": "/f2", "status": 200, "hits": 3},
        ]
    finally:
        conn.close()


def test_per_client_cap_keeps_order(sampling_db):
    conn = connect(sampling_db, read_only=True)
    try:
        batched = queries.sample_paths_for_clients(conn, _filt(), [_p("203.0.113.61")])
        assert batched[_p("203.0.113.61")] == [
            {"path": "/p1", "status": 200, "hits": 3},
            {"path": "/p1", "status": 404, "hits": 1},
            {"path": "/p2", "status": 404, "hits": 1},
            {"path": "/p3", "status": 404, "hits": 1},
            {"path": "/p4", "status": 404, "hits": 1},
        ]
    finally:
        conn.close()


def test_filters_apply_before_grouping(sampling_db):
    target = [_p("203.0.113.62")]
    conn = connect(sampling_db, read_only=True)
    try:
        assert queries.sample_paths_for_clients(conn, _filt(status=404), target)[target[0]] == [
            {"path": "/f1", "status": 404, "hits": 5}
        ]
        assert queries.sample_paths_for_clients(conn, _filt(status_class="4xx"), target)[
            target[0]
        ] == [{"path": "/f1", "status": 404, "hits": 5}]
        assert queries.sample_paths_for_clients(conn, _filt(path_prefix="/f2"), target)[
            target[0]
        ] == [{"path": "/f2", "status": 200, "hits": 3}]
        assert queries.sample_paths_for_clients(conn, _filt(search="/f1"), target)[target[0]] == [
            {"path": "/f1", "status": 404, "hits": 5}
        ]
        # No POST rows exist: the filter narrows, never widens.
        assert queries.sample_paths_for_clients(conn, _filt(method="POST"), target)[target[0]] == []
    finally:
        conn.close()


def test_window_bounds(sampling_db):
    target = [_p("203.0.113.63")]
    conn = connect(sampling_db, read_only=True)
    try:
        in_window = queries.sample_paths_for_clients(conn, _filt(), target)
        assert in_window[target[0]] == [{"path": "/w1", "status": 404, "hits": 5}]
        wide = queries.sample_paths_for_clients(conn, _filt(window=WIDE_WINDOW), target)
        assert wide[target[0]] == [
            {"path": "/w1", "status": 404, "hits": 5},
            {"path": "/w2", "status": 404, "hits": 4},
        ]
        assert (
            queries.sample_paths_for_clients(conn, _filt(window=EMPTY_WINDOW), target)[target[0]]
            == []
        )
    finally:
        conn.close()


def test_cross_site_isolation(sampling_db):
    target = [_p("203.0.113.64")]
    conn = connect(sampling_db, read_only=True)
    try:
        assert queries.sample_paths_for_clients(conn, _filt(), target)[target[0]] == []
        other = queries.sample_paths_for_clients(conn, _filt(site_id="other"), target)[target[0]]
        assert other == [{"path": "/s1", "status": 404, "hits": 5}]
    finally:
        conn.close()


def test_cross_source_narrowing(sampling_db):
    target = [_p("203.0.113.65")]
    conn = connect(sampling_db, read_only=True)
    try:
        both = queries.sample_paths_for_clients(conn, _filt(), target)[target[0]]
        assert both == [
            {"path": "/q1", "status": 404, "hits": 3},
            {"path": "/q2", "status": 404, "hits": 3},
        ]
        only_a = queries.sample_paths_for_clients(
            conn, _filt(source_id="example-combined"), target
        )[target[0]]
        assert only_a == [{"path": "/q1", "status": 404, "hits": 3}]
        only_b = queries.sample_paths_for_clients(conn, _filt(source_id="second-combined"), target)[
            target[0]
        ]
        assert only_b == [{"path": "/q2", "status": 404, "hits": 3}]
    finally:
        conn.close()


def test_classifier_filter_applies_before_grouping(sampling_db):
    targets = [_p("203.0.113.66"), _p("203.0.113.67")]
    conn = connect(sampling_db, read_only=True)
    try:
        clf = _clf()
        claimed = queries.sample_paths_for_clients(
            conn, _filt(traffic="claimed_bot"), targets, classifier=clf
        )
        assert claimed[targets[0]] == [{"path": "/g1", "status": 404, "hits": 5}]
        assert claimed[targets[1]] == []
        for target in targets:
            single = queries.sample_paths_for_client(
                conn,
                _filt(traffic="claimed_bot"),
                client_pseudonym=target,
                classifier=clf,
            )
            assert claimed[target] == single
    finally:
        conn.close()


def test_empty_request_list_is_cheap(sampling_db):
    conn = connect(sampling_db, read_only=True)
    try:
        seen: list[str] = []
        conn.set_trace_callback(seen.append)
        try:
            assert queries.sample_paths_for_clients(conn, _filt(), []) == {}
        finally:
            conn.set_trace_callback(None)
        assert seen == []
    finally:
        conn.close()


def test_client_and_row_bounds_with_single_query(cap_db):
    filt = _filt()
    conn = connect(cap_db, read_only=True)
    try:
        candidates = queries.repeated_client_errors(conn, filt, min_errors=5)
        assert len(candidates) == 100  # 101st client exceeds the repeated-error cap
        requested = [str(c["client_pseudonym"]) for c in candidates]
        extra = _p("198.51.100.101")
        if extra in requested:
            extra = "missing-pseudonym"
            assert extra not in requested
        seen: list[str] = []
        conn.set_trace_callback(seen.append)
        try:
            batched = queries.sample_paths_for_clients(conn, filt, [*requested, extra])
        finally:
            conn.set_trace_callback(None)
        assert len(batched) == 101
        assert batched[extra] == []
        assert sum(len(rows) for rows in batched.values()) == 500
        assert len(seen) == 1  # one batched scan replaces 101 per-client scans
    finally:
        conn.close()


def test_security_findings_keep_counts_order_and_samples(sampling_db):
    conn = connect(sampling_db, read_only=True)
    try:
        findings = service.security_findings(conn, _filt(), SEC_RULES)
    finally:
        conn.close()
    assert [f.rule_id for f in findings].count("sec-repeated-client-errors") == 7
    by_client = {
        f.evidence["client_pseudonym"]: f
        for f in findings
        if f.rule_id == "sec-repeated-client-errors"
    }
    # distinct_paths counts 4xx rows only: /a + /b (the /c 500s are errors elsewhere).
    assert by_client[_p("203.0.113.60")].counts == {"errors": 6, "distinct_paths": 2}
    assert by_client[_p("203.0.113.60")].evidence["sample_paths"] == [
        {"path": "/a", "status": 404, "hits": 3},
        {"path": "/b", "status": 404, "hits": 3},
        {"path": "/c", "status": 500, "hits": 2},
        {"path": "/a", "status": 200, "hits": 1},
    ]
    assert by_client[_p("203.0.113.61")].counts == {"errors": 7, "distinct_paths": 7}
    assert by_client[_p("203.0.113.65")].counts == {"errors": 6, "distinct_paths": 2}
    errors = [f.counts["errors"] for f in findings]
    assert errors == sorted(errors, reverse=True)
    assert all(f.coverage_summary["unique_events"] > 0 for f in findings)


def test_security_findings_empty_window(sampling_db):
    conn = connect(sampling_db, read_only=True)
    try:
        assert service.security_findings(conn, _filt(window=EMPTY_WINDOW), SEC_RULES) == []
    finally:
        conn.close()

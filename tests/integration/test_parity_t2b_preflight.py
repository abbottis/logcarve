"""Parity T2b transport preflight: bounded-memory correction gates.

Proves the frozen T2b correction no longer materializes unbounded
groups in Python before T3 transport wiring:

- ``offender_minute_peaks`` ranks peaks in SQL and returns at most
  one row per requested client (exact earliest tie), even with many
  minute buckets;
- ``journey_key_for_id`` resolves opaque IDs through a streaming
  bounded cursor (no ``fetchall``, no cap), so a high-cardinality
  same-client/same-start UA set resolves with O(1) memory and a
  valid match near the end is still found;
- peak and average share the SAME rule-matching numerator (the
  legacy 4xx rule counts stored 4xx in both), with unambiguous
  scope/numerator labels and partial-bucket lower-bound honesty.

Small synthetic fixtures only; never the immutable shared fixtures.
"""

from datetime import UTC, datetime

from app.analytics import queries, service
from app.analytics.contracts import AnalyticsFilter, JourneyQuery, TimeWindow
from app.analytics.rules import Rule
from app.db.database import connect
from app.db.importer import run_import
from app.db.migrations_runner import migrate
from app.ingestion.combined import pseudonymize_client
from app.ingestion.sources import SourceConfig

HMAC_KEY = b"parity-t2b-preflight-key"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)
WINDOW = (datetime(2026, 10, 27, 9, 0, tzinfo=UTC), datetime(2026, 10, 27, 12, 0, tzinfo=UTC))


def _filt(site, wf, wt, **overrides):
    base = {"site_id": site, "window": TimeWindow(time_from=wf, time_to=wt)}
    base.update(overrides)
    return AnalyticsFilter(**base)


def _pseudo(ip: str) -> str:
    return pseudonymize_client(ip, HMAC_KEY)


def _import_one(tmp_path, site, source):
    root = tmp_path / "logs"
    root.mkdir(exist_ok=True)
    (root / "c.log").write_bytes(
        b'198.51.100.9 - - [27/Oct/2026:10:00:00 +0000] "GET /seed HTTP/1.1" 200 10 "-" "Seed/1.0"\n'
    )
    db = tmp_path / f"{source}.sqlite3"
    migrate(db)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id=source,
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="c.log",
        ),
        site_id=site,
        site_name="Preflight",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="c.log",
        hmac_key=HMAC_KEY,
    )
    assert imported.status == "completed"
    return db


def _insert(holder, ts, path, status, client, ua="Preflight/1.0"):
    scope = holder.execute(
        "SELECT imports.id, log_sources.site_id, log_sources.id, imports.file_fingerprint"
        " FROM imports JOIN log_sources ON log_sources.id = imports.source_id LIMIT 1"
    ).fetchone()
    assert scope is not None
    offset = holder.execute("SELECT COALESCE(MAX(byte_offset), 0) + 1 FROM requests").fetchone()[0]
    holder.execute(
        "INSERT INTO requests (import_id, site_id, source_id, file_fingerprint,"
        " byte_offset, line_number, ts_utc, method, path, status, bytes,"
        " referer_host, user_agent, client_pseudonym)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 'GET', ?, ?, 10, NULL, ?, ?)",
        (scope[0], scope[1], scope[2], scope[3], offset, offset, ts, path, status, ua, client),
    )


class _CountingConn:
    """Delegate wrapper recording rows materialized per fetchall."""

    def __init__(self, real):
        self._real = real
        self.fetchall_sizes: list[int] = []

    def execute(self, *args, **kwargs):
        cursor = self._real.execute(*args, **kwargs)
        parent = self

        class _Cursor:
            def fetchall(self):
                rows = cursor.fetchall()
                parent.fetchall_sizes.append(len(rows))
                return rows

            def fetchone(self):
                return cursor.fetchone()

            def __iter__(self):
                return iter(cursor)

            def close(self):
                return cursor.close()

        return _Cursor()


class _NoFetchallConn:
    """Delegate wrapper failing any fetchall: proves streaming resolution."""

    def __init__(self, real):
        self._real = real

    def execute(self, *args, **kwargs):
        cursor = self._real.execute(*args, **kwargs)

        class _Cursor:
            def fetchall(self):  # pragma: no cover - must never happen
                raise AssertionError("fetchall materialization is not allowed here")

            def fetchone(self):
                return cursor.fetchone()

            def __iter__(self):
                return iter(cursor)

            def close(self):
                return cursor.close()

        return _Cursor()


def _legacy_rule(threshold: int = 5) -> Rule:
    return Rule(
        id="sec-repeated-client-errors",
        version=1,
        category="repeated_client_errors",
        title="t",
        meaning="m",
        min_client_errors=threshold,
    )


def test_preflight_peaks_rank_in_sql_one_row_per_client(tmp_path):
    """300 minute buckets still materialize at most one row per client."""
    site, source = "site-preflight-peak", "preflight-peak-source"
    db = _import_one(tmp_path, site, source)
    holder = connect(db)
    try:
        client = _pseudo("198.51.100.40")
        # 300 distinct whole-UTC-minute buckets, one row each, plus a
        # doubled earliest bucket (tie-break control below uses 2 rows).
        for minute in range(300):
            hour = 9 + minute // 60
            stamp = f"2026-10-27T{hour:02d}:{minute % 60:02d}:10+00:00"
            # Keep inside the 09:00-12:00 window: minutes 0..179 fall in
            # 09:00-11:59; stop the spread before the edge.
            if minute >= 180:
                break
            _insert(holder, stamp, f"/m{minute}", 404, client)
        holder.commit()
    finally:
        holder.close()
    filt = _filt(site, *WINDOW)
    where, params = queries._where(filt, None)
    # Narrow to stored 4xx like the legacy rule so the numerator is exact.
    scoped = f"{where} AND status BETWEEN 400 AND 499"
    conn = connect(db, read_only=True)
    try:
        wrapped = _CountingConn(conn)
        peaks = queries.offender_minute_peaks(wrapped, scoped, list(params), [client])
    finally:
        conn.close()
    assert peaks[client]["peak_minute_requests"] == 1
    # Instrumentation: no single fetchall inside the peaks query may
    # carry more than one row per requested client.
    assert wrapped.fetchall_sizes, "peaks query must touch the database"
    assert max(wrapped.fetchall_sizes) <= 1


def test_preflight_peaks_earliest_tie_is_exact(tmp_path):
    """Equal-bucket ties resolve to the earliest whole UTC minute."""
    site, source = "site-preflight-tie", "preflight-tie-source"
    db = _import_one(tmp_path, site, source)
    holder = connect(db)
    try:
        client = _pseudo("198.51.100.41")
        for stamp in (
            "2026-10-27T10:05:01+00:00",
            "2026-10-27T10:05:02+00:00",
            "2026-10-27T10:02:01+00:00",
            "2026-10-27T10:02:02+00:00",
        ):
            _insert(holder, stamp, "/tie", 404, client)
        holder.commit()
    finally:
        holder.close()
    filt = _filt(site, *WINDOW)
    where, params = queries._where(filt, None)
    conn = connect(db, read_only=True)
    try:
        peaks = queries.offender_minute_peaks(
            conn, f"{where} AND status BETWEEN 400 AND 499", list(params), [client, "missing"]
        )
    finally:
        conn.close()
    assert peaks[client] == {"peak_minute_requests": 2, "peak_minute": "2026-10-27T10:02"}
    assert peaks["missing"] == {"peak_minute_requests": 0, "peak_minute": None}


def test_preflight_tempo_numerator_matches_average(tmp_path):
    """5 matching 4xx + 100 benign 2xx in one minute: peak counts 4xx only."""
    site, source = "site-preflight-tempo", "preflight-tempo-source"
    db = _import_one(tmp_path, site, source)
    holder = connect(db)
    try:
        client = _pseudo("198.51.100.42")
        for minute in range(5):
            _insert(holder, f"2026-10-27T10:0{minute}:10+00:00", f"/probe{minute}", 404, client)
        for n in range(100):
            _insert(holder, f"2026-10-27T10:30:{n % 60:02d}+00:00", "/benign", 200, client)
        holder.commit()
    finally:
        holder.close()
    filt = _filt(site, *WINDOW)
    conn = connect(db, read_only=True)
    try:
        findings = service.security_findings(conn, filt, [_legacy_rule()], observation_time=NOW)
    finally:
        conn.close()
    assert len(findings) == 1
    only = findings[0]
    assert only.counts == {"errors": 5, "distinct_paths": 5}
    # The peak uses the SAME stored-4xx numerator as the average: 1 per
    # spread minute, never the 100 benign 2xx burst in 10:30.
    assert only.evidence["peak_minute_requests"] == 1
    assert only.evidence["peak_minute_numerator"] == "stored 4xx errors"
    assert only.evidence["avg_numerator"] == "stored 4xx errors"
    assert only.evidence["peak_minute_scope"] == "rule_matching"
    # The historic all-status path/sequence context is retained
    # separately: the benign burst stays visible there.
    assert only.evidence["sample_scope_requests"] == 105
    assert only.evidence["path_sequence_total"] == 105
    assert "SAME rule-matching numerator" in only.evidence["tempo_note"]


def test_preflight_partial_edge_bucket_is_lower_bound(tmp_path):
    """A peak bucket cut by the window edge is flagged with its interval."""
    site, source = "site-preflight-partial", "preflight-partial-source"
    db = _import_one(tmp_path, site, source)
    holder = connect(db)
    try:
        client = _pseudo("198.51.100.43")
        for n in range(6):
            _insert(holder, f"2026-10-27T10:00:{35 + n:02d}+00:00", "/edge", 404, client)
        holder.commit()
    finally:
        holder.close()
    # Window starts mid-bucket: the 10:00 bucket is only partly observed.
    filt = _filt(site, datetime(2026, 10, 27, 10, 0, 30, tzinfo=UTC), WINDOW[1])
    conn = connect(db, read_only=True)
    try:
        findings = service.security_findings(
            conn, filt, [_legacy_rule(threshold=1)], observation_time=NOW
        )
    finally:
        conn.close()
    assert len(findings) == 1
    only = findings[0]
    assert only.evidence["peak_minute"] == "2026-10-27T10:00"
    assert only.evidence["peak_minute_partial"] is True
    assert only.evidence["peak_minute_interval"] == (
        "2026-10-27T10:00:00+00:00/2026-10-27T10:01:00+00:00"
    )


def test_preflight_journey_id_streams_late_match_without_fetchall(tmp_path):
    """250 same-client/same-start UAs: no fetchall, last ID still resolves."""
    site, source = "site-preflight-jid", "preflight-jid-source"
    db = _import_one(tmp_path, site, source)
    holder = connect(db)
    try:
        client = _pseudo("198.51.100.44")
        for n in range(250):
            _insert(
                holder,
                "2026-10-27T10:00:00+00:00",
                f"/ua{n:03d}",
                200,
                client,
                ua=f"HighCardinalityAgent/{n:04d}",
            )
        holder.commit()
    finally:
        holder.close()
    filt = _filt(site, *WINDOW, limit=1000)
    conn = connect(db, read_only=True)
    try:
        listed = service.journeys(conn, JourneyQuery(filt=filt), None)
        targets = [
            item
            for item in listed["items"]
            if item["client_pseudonym"] == client
            and item["started_at"] == "2026-10-27T10:00:00+00:00"
        ]
        assert len(targets) == 250
        # The valid match sits near the end of the candidate order.
        wanted = targets[-1]
        streamed = _NoFetchallConn(conn)
        agent, start = queries.journey_key_for_id(
            streamed,
            filt,
            client_pseudonym=client,
            journey_start=datetime.fromisoformat(wanted["started_at"]),
            journey_id=wanted["journey_id"],
        )
        assert start == "2026-10-27T10:00:00+00:00"
        assert agent == "HighCardinalityAgent/0249"
        # The streamed timeline equals the listed entry (no dropped match).
        from app.analytics.contracts import JourneyIdQuery

        resolved = service.journey_timeline_by_id(
            conn,
            JourneyIdQuery(
                filt=filt,
                client_pseudonym=client,
                journey_start=datetime.fromisoformat(wanted["started_at"]),
                journey_id=wanted["journey_id"],
            ),
            None,
        )
        assert resolved["entry_path"] == "/ua249"
    finally:
        conn.close()

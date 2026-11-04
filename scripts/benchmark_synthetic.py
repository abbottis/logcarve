#!/usr/bin/env python3
"""Maintained synthetic scale benchmark: 100k/1M rows (T5b3, OPS-03).

Generates a deterministic synthetic access log OUTSIDE Git (TMPDIR),
imports it, replays it, and times the import, replay, peak RSS, DB
size, representative analytics queries and a full export row count.
For scopes above the documented export cap the harness executes the
real authenticated export rejection (tiny HTTP 413, no provider)
instead of streaming; below the cap it streams rows through the
bounded server cursor and labels that proof as cursor-level, never as
an HTTP download.

The fixture is fully synthetic (documentation addresses, example
domains) with hand-derived expectations from the generation rules, so
expected and observed counts are printed side by side. No real logs,
no live database, no secrets and no model calls are ever involved.
The fixture hash streams in 1 MiB chunks (never a whole-file read),
and both the import-phase RSS peak and the final overall peak are
reported honestly by label.

The coordinator owns the expensive final runs (100k and 1M); this file
only has to stay runnable and honest. A small ``--rows`` smoke run is
covered by the test suite.

Usage:
    python scripts/benchmark_synthetic.py --rows 100000 --seed 20261102
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import resource
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

EXPORT_MAX_ROWS = 250_000

BASE_TS = datetime(2026, 10, 29, tzinfo=UTC)
HOSTS = ("203.0.113.10", "203.0.113.11", "198.51.100.7", "192.0.2.44", "2001:db8::25")
PATHS = ("/", "/docs/", "/docs/exact", "/api/events", "/style.css", "/app.js", "/old")
AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64)",
    "curl/8.0",
    "TestBot/1.0 (+https://example.org/bot)",
    "SearchCrawler/2.1",
)
REFERRERS = ("-", "https://example.org/old", "https://example.org/docs/page?x=1")


def _request_time_ms(index: int, seed: int) -> float:
    bucket = ((index * 2654435761 + seed) % 1000) / 1000.0
    if bucket < 0.80:
        return 10.0 + (index % 70)
    if bucket < 0.95:
        return 200.0 + (index % 600)
    return 1500.0 + (index % 1500)


def _status(index: int) -> int:
    if index % 100 == 99:
        return 500
    if index % 200 == 199:
        return 403
    if index % 20 == 19:
        return 404
    return 200


def gen_line(index: int, seed: int) -> str | None:
    """One deterministic extended line, or ``None`` for a known-invalid line."""
    if index % 1000 == 999:
        return "NOT A LOG LINE AT ALL\n"
    host = HOSTS[index % len(HOSTS)]
    path = PATHS[index % len(PATHS)]
    agent = AGENTS[index % len(AGENTS)]
    referer = REFERRERS[index % len(REFERRERS)]
    status = _status(index)
    size = 100 + (index % 5000)
    moment = BASE_TS + timedelta(seconds=index % 86400)
    stamp = moment.strftime("%d/%b/%Y:%H:%M:%S +0000")
    rt_ms = _request_time_ms(index, seed)
    rt_s = f"{rt_ms / 1000.0:.3f}"
    upstream = "-" if index % 3 else f"{(rt_ms / 2000.0) / 1000.0:.3f}"
    cache = ("HIT", "MISS", "-")[index % 3]
    mime = ("text/html", "text/css", "application/json")[index % 3]
    method = "POST" if index % 37 == 36 else "GET"
    return (
        f'{host} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size}'
        f' "{referer}" "{agent}" example.org {cache} {rt_s} {mime} TLSv1.3 "{upstream}"\n'
    )


def expected_counts(rows: int, seed: int) -> dict[str, int]:
    rejected = sum(1 for i in range(rows) if i % 1000 == 999)
    accepted = rows - rejected
    slow = sum(1 for i in range(rows) if i % 1000 != 999 and _request_time_ms(i, seed) >= 1000.0)
    not_found = sum(1 for i in range(rows) if i % 1000 != 999 and _status(i) == 404)
    return {
        "rows": rows,
        "rejected": rejected,
        "accepted": accepted,
        "slow_ge_1000ms": slow,
        "status_404": not_found,
    }


def _rss_mb() -> tuple[float, str]:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return usage / (1024 * 1024), "MiB (ru_maxrss bytes on macOS)"
    return usage / 1024.0, "MiB (ru_maxrss kilobytes on Linux)"


def _probe_export_413(db: Path, total: int) -> dict:
    """Execute the real authenticated export-cap rejection (tiny, no provider).

    Mints a genuine ``analytics:read`` token on the temporary synthetic
    DB, serves the real app in-process, and requests the CSV export with
    the route cap temporarily forced to zero so the identical
    count-then-reject code answers HTTP 413 ``export_too_large``. The
    production cap is restored afterwards. Returns an honest record:
    ``exercised`` is true only when a 413 was actually observed; any
    setup failure marks the check NOT RUN instead of fabricating it.
    """
    probe: dict = {"exercised": False}
    if total < 1:
        probe["reason"] = "NOT RUN: empty scope cannot exceed the cap"
        return probe
    try:
        import os

        from starlette.testclient import TestClient

        # Synthetic probe-only defaults for the settings the app
        # requires at startup; operator-provided values always win,
        # and nothing here touches the real credential stores.
        os.environ.setdefault("SESSION_SECRET", "bench-probe-session-secret")
        os.environ.setdefault("HMAC_KEY", "bench-probe-hmac-key")

        from app.api import routes_export as routes_export_mod
        from app.auth.tokens import issue_token
        from app.db.database import writer_transaction
        from app.main import create_app
    except Exception as exc:  # noqa: BLE001 - record why the probe could not run
        probe["reason"] = f"NOT RUN: probe dependencies unavailable: {type(exc).__name__}"
        return probe
    try:
        with writer_transaction(db) as conn:
            _token_id, plaintext = issue_token(conn, name="bench-413", site_id="default")
        app = create_app(db_path=db, secure_cookies=False)
        client = TestClient(app, raise_server_exceptions=False)
        previous = routes_export_mod.EXPORT_MAX_ROWS
        routes_export_mod.EXPORT_MAX_ROWS = 0
        try:
            response = client.get(
                "/api/v1/exports/requests",
                params={
                    "site_id": "default",
                    "from": BASE_TS.isoformat(),
                    "to": (BASE_TS + timedelta(days=1)).isoformat(),
                    "export_format": "csv",
                },
                headers={"Authorization": f"Bearer {plaintext}"},
            )
            status, code = response.status_code, None
            try:
                code = response.json().get("code")
            except Exception:  # noqa: BLE001 - non-JSON body still counts as observed
                code = None
        finally:
            routes_export_mod.EXPORT_MAX_ROWS = previous
        probe.update(
            {
                "exercised": status == 413 and code == "export_too_large",
                "http_status": status,
                "code": code,
                "probe_cap_rows": 0,
                "note": "same authenticated route with a forced probe cap;"
                " production cap unchanged",
            }
        )
        if not probe["exercised"]:
            probe["reason"] = "NOT RUN: rejection path did not answer 413 as expected"
    except Exception as exc:  # noqa: BLE001 - honest record, never a fabricated pass
        probe["reason"] = f"NOT RUN: probe failed: {type(exc).__name__}"
    return probe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic scale benchmark (coordinator runs).")
    parser.add_argument("--rows", type=int, default=100000)
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--db", default=None, help="Database file (default: temp, outside Git)")
    parser.add_argument("--out", default=None, help="Write the JSON summary to this file")
    parser.add_argument("--batch-size", type=int, default=5000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.rows < 1:
        print("error: --rows must be positive", file=sys.stderr)
        return 2
    expected = expected_counts(args.rows, args.seed)
    tmpdir = Path(tempfile.mkdtemp(prefix="logcarve-bench-"))
    fixture = tmpdir / "bench.log"
    started = time.perf_counter()
    with open(fixture, "w", encoding="utf-8") as stream:
        stream.writelines(gen_line(index, args.seed) for index in range(args.rows))
    gen_s = time.perf_counter() - started
    # Stream the hash in bounded chunks: a 1M-row fixture is tens of
    # megabytes and must never be read whole into memory for hashing.
    digest = hashlib.sha256()
    with open(fixture, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    fixture_sha = digest.hexdigest()
    db = Path(args.db) if args.db else tmpdir / "bench.sqlite3"
    if db.exists() and db.stat().st_size > 0:
        print(f"error: refusing non-empty database: {db}", file=sys.stderr)
        return 2

    from app.analytics import service as analytics_service
    from app.analytics.contracts import (
        AnalyticsFilter,
        JourneyQuery,
        SlowEndpointsQuery,
        TimeWindow,
    )
    from app.analytics.rules import load_rules
    from app.db.database import connect
    from app.db.importer import run_import
    from app.ingestion.combined import NGINX_EXTENDED
    from app.ingestion.sources import SourceConfig

    filt = AnalyticsFilter(
        site_id="default",
        window=TimeWindow(time_from=BASE_TS, time_to=BASE_TS + timedelta(days=1)),
    )
    rules_dir = REPO_ROOT / "config"
    rules = (
        load_rules(rules_dir / "bot_rules.yaml").rules
        + load_rules(rules_dir / "security_rules.yaml").rules
    )
    source = SourceConfig(
        source_id="bench", format_id=NGINX_EXTENDED, allowed_root=tmpdir, relative_path="bench.log"
    )
    started = time.perf_counter()
    first = run_import(
        db,
        source=source,
        site_id="default",
        site_name="Benchmark",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="bench.log",
        hmac_key=b"benchmark-hmac-key",
        batch_size=args.batch_size,
    )
    import_s = time.perf_counter() - started
    if first.status != "completed":
        print(f"error: import failed: {first.error_summary}", file=sys.stderr)
        return 1
    # Import-phase peak only: later queries/streaming may push higher,
    # so the final overall peak is sampled separately below and both
    # are labeled honestly.
    import_peak_mb, rss_unit = _rss_mb()
    db_bytes = db.stat().st_size
    started = time.perf_counter()
    second = run_import(
        db,
        source=source,
        site_id="default",
        site_name="Benchmark",
        site_hostname="example.org",
        server_type="nginx",
        path_alias="bench.log",
        hmac_key=b"benchmark-hmac-key",
        batch_size=args.batch_size,
    )
    replay_s = time.perf_counter() - started

    timings: dict[str, float] = {}
    conn = connect(db, read_only=True)
    try:
        current_filter = filt
        for name, call in (
            ("coverage", lambda: analytics_service.coverage_summary(conn, current_filter, rules)),
            (
                "performance",
                lambda: analytics_service.performance_overview(conn, current_filter, rules),
            ),
            (
                "slow_endpoints",
                lambda: analytics_service.slow_endpoints(
                    conn,
                    SlowEndpointsQuery(
                        filt=current_filter.model_copy(update={"timing_min_ms": 1000.0})
                    ),
                    None,
                ),
            ),
            (
                "journeys",
                lambda: analytics_service.journeys(conn, JourneyQuery(filt=current_filter), None),
            ),
            ("security", lambda: analytics_service.security_findings(conn, current_filter, rules)),
            ("country", lambda: analytics_service.country_breakdown(conn, current_filter, rules)),
        ):
            begin = time.perf_counter()
            call()
            timings[name] = time.perf_counter() - begin
        # Full export row count within the cap through the bounded
        # server cursor (cursor-level proof, not an HTTP download).
        # Above the cap nothing streams: the real authenticated HTTP
        # 413 rejection is executed separately below.
        from app.analytics import queries as analytics_queries

        total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        export_rows: int | None = None
        export_stream_proof: str | None = None
        if total <= EXPORT_MAX_ROWS:
            begin = time.perf_counter()
            count = 0
            for _row in analytics_queries.iter_export_rows(
                conn,
                current_filter,
                analytics_service.classifier_for_filter(current_filter, rules),
                "newest",
            ):
                count += 1
            timings["export_stream"] = time.perf_counter() - begin
            export_rows = count
            export_stream_proof = "cursor"
    finally:
        conn.close()
    export_413_probe = _probe_export_413(db, total)

    slow_observed = None
    conn = connect(db, read_only=True)
    try:
        slow_observed = conn.execute(
            "SELECT COUNT(*) FROM requests WHERE request_time_ms >= 1000.0"
        ).fetchone()[0]
    finally:
        conn.close()
    # Final overall peak: the import-phase peak above is NOT the whole
    # run when queries/streaming/probing pushed higher afterwards.
    overall_peak_mb, _overall_unit = _rss_mb()
    summary = {
        "rows": args.rows,
        "seed": args.seed,
        "environment": {
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "rss_unit": rss_unit,
        },
        "fixture": {
            "path": "temporary (outside Git, removed only by the operator)",
            "sha256": fixture_sha,
            "generate_s": round(gen_s, 3),
        },
        "expected": expected,
        "observed": {
            "import_status": first.status,
            "lines_accepted": first.lines_accepted,
            "lines_rejected": first.lines_rejected,
            "records_inserted": first.records_inserted,
            "records_replayed": second.records_replayed,
            "slow_ge_1000ms": slow_observed,
            "export_rows": export_rows,
            "export_stream_proof": export_stream_proof,
            "export_413_probe": export_413_probe,
        },
        "measurements": {
            "import_s": round(import_s, 3),
            "replay_s": round(replay_s, 3),
            "peak_rss_import_mib": round(import_peak_mb, 1),
            "peak_rss_overall_mib": round(overall_peak_mb, 1),
            "db_bytes": db_bytes,
            "query_s": {name: round(value, 3) for name, value in timings.items()},
        },
        "cap": {"export_max_rows": EXPORT_MAX_ROWS},
    }
    ok = (
        first.lines_accepted == expected["accepted"]
        and first.lines_rejected == expected["rejected"]
        and first.records_inserted == expected["accepted"]
        and second.records_inserted == 0
        and second.records_replayed == expected["accepted"]
        and slow_observed == expected["slow_ge_1000ms"]
        and (export_rows == expected["accepted"] if export_rows is not None else True)
    )
    summary["verdict"] = "match" if ok else "MISMATCH"
    text = json.dumps(summary, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

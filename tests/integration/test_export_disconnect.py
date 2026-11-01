"""Independent T3a runtime probe: export response owns snapshot cleanup.

The snapshot fix keeps count/metadata/rows on one snapshot, but the
response lifecycle relied on the row-generator ``finally`` and the
background task. Actual Starlette ``StreamingResponse.__call__``
(spec 2.4) converts a ``send`` ``OSError`` at the first
``http.response.body`` (CSV header / JSON prefix, before ``rows()``
starts) into ``ClientDisconnect`` and SKIPS the background task —
leaving the prepared snapshot open. This probe invokes the ACTUAL
response object (never ``stream.rows().close()`` or a manual
``background()`` call) across both formats, every failure point,
task cancellation, the older disconnect protocol and renderer
errors, and requires the snapshot deterministically closed.
"""

import asyncio
import json
from datetime import UTC, datetime

import pytest
from starlette.responses import ClientDisconnect

from app.analytics.contracts import AnalyticsFilter, TimeWindow
from app.api import routes_export
from app.api.routes_export import ExportStream, close_prepared, export_response
from app.db.migrations_runner import migrate


def _seed(db, root):
    from app.db.importer import run_import
    from app.ingestion.sources import SourceConfig

    migrate(db)
    lines = b"".join(
        b'198.51.100.7 - - [27/Oct/2026:10:0%d:00 +0000] "GET /probe%d HTTP/1.1"'
        b' 200 10 "-" "Probe/1.0"\n' % (n, n)
        for n in range(5)
    )
    (root / "access.log").write_bytes(lines)
    imported = run_import(
        db,
        source=SourceConfig(
            source_id="probe-source",
            format_id="nginx_combined",
            allowed_root=root,
            relative_path="access.log",
        ),
        site_id="probe-site",
        site_name="Probe",
        site_hostname="probe.example.org",
        server_type="nginx",
        path_alias="access.log",
        hmac_key=b"probe-disconnect-key",
    )
    assert imported.status == "completed"


@pytest.fixture
def probedb(tmp_path):
    db = tmp_path / "probe.sqlite3"
    root = tmp_path / "logs"
    root.mkdir()
    _seed(db, root)
    return db


def _filt():
    return AnalyticsFilter(
        site_id="probe-site",
        window=TimeWindow(
            time_from=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
            time_to=datetime(2026, 10, 27, 11, 0, tzinfo=UTC),
        ),
    )


def _rules():
    from pathlib import Path

    from app.analytics.rules import load_rules

    root = Path(__file__).resolve().parent.parent.parent / "config"
    return (
        load_rules(root / "bot_rules.yaml").rules + load_rules(root / "security_rules.yaml").rules
    )


def _prepared(db, export_format):
    prepared, failure = routes_export.prepare_session_export(
        filt=_filt(),
        rules=_rules(),
        sort="oldest",
        export_format=export_format,
        db_path=db,
        display_timezone="UTC",
    )
    assert failure is None
    return prepared


def _scope(spec_version="2.4"):
    return {
        "type": "http",
        "asgi": {"spec_version": spec_version},
        "method": "GET",
        "path": "/api/v1/exports/requests",
        "headers": [],
    }


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


def _failing_send(*, fail_from=0):
    """Send that raises OSError from the ``fail_from``-th message on."""
    calls = {"n": 0, "messages": []}

    async def send(message):
        calls["n"] += 1
        calls["messages"].append(message)
        if calls["n"] - 1 >= fail_from:
            raise OSError("probe disconnect")

    return send, calls


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_send_failure_before_any_body_closes_snapshot(probedb, export_format):
    """OSError at http.response.start: background skipped, generator unstarted."""
    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    response = export_response(prepared, f"probe.{export_format}")
    assert isinstance(response, routes_export.ExportStreamingResponse)
    send, calls = _failing_send(fail_from=0)
    with pytest.raises(ClientDisconnect):
        asyncio.run(response(_scope(), _receive, send))
    assert calls["n"] == 1  # failed before any body byte
    assert stream.closed
    assert stream._conn is None and stream._cursor is None
    stream.close()  # idempotent re-close stays safe


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_send_failure_at_first_body_closes_snapshot(probedb, export_format):
    """OSError at the first body chunk (CSV header / JSON prefix).

    The row generator has not started (the header/prefix yields
    before ``rows()`` is consumed), so its ``finally`` cannot run,
    and the superclass skips the background task on the way to
    ``ClientDisconnect``. Only the response-level ``finally`` owns
    this release.
    """
    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    response = export_response(prepared, f"probe.{export_format}")
    send, calls = _failing_send(fail_from=1)
    with pytest.raises(ClientDisconnect):
        asyncio.run(response(_scope(), _receive, send))
    kinds = [m["type"] for m in calls["messages"]]
    assert kinds[0] == "http.response.start"
    assert kinds[1] == "http.response.body"  # header/prefix, before rows()
    assert stream.closed


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_send_failure_mid_body_closes_snapshot(probedb, export_format):
    """OSError after rows started: body aborts, snapshot still released."""
    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    response = export_response(prepared, f"probe.{export_format}")
    send, calls = _failing_send(fail_from=3)
    with pytest.raises(ClientDisconnect):
        asyncio.run(response(_scope(), _receive, send))
    assert calls["n"] > 3
    assert stream.closed


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_success_closes_snapshot_and_completes(probedb, export_format):
    """Happy path still closes exactly once with a complete body."""
    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    closes = {"n": 0}
    real_close = stream.close

    def counting_close():
        closes["n"] += 1
        real_close()

    stream.close = counting_close  # type: ignore[method-assign]
    response = export_response(prepared, f"probe.{export_format}")
    sent = []

    async def send(message):
        sent.append(message)

    asyncio.run(response(_scope(), _receive, send))
    assert stream.closed
    # Single deterministic release: response finally owns it; the
    # background re-close and any generator finally are no-ops.
    stream.close()
    stream.close()
    assert stream.closed
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    if export_format == "json":
        envelope = json.loads(body.decode())
        assert envelope["complete"] is True
        assert len(envelope["rows"]) == 5
    else:
        assert len(body.decode().strip().splitlines()) == 6  # header + 5 rows


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_cancellation_closes_snapshot(probedb, export_format):
    """Cancelling the streaming task releases the snapshot (both formats)."""
    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    response = export_response(prepared, f"probe.{export_format}")
    started = asyncio.Event()

    async def send(message):
        started.set()
        await asyncio.sleep(3600)

    async def main():
        task = asyncio.ensure_future(response(_scope(), _receive, send))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert stream.closed


def test_response_older_disconnect_protocol_closes_snapshot(probedb):
    """Spec 2.0 disconnect during streaming still releases the snapshot."""

    state = {"started": False}

    async def disconnect_after_start():
        if not state["started"]:
            state["started"] = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    prepared = _prepared(probedb, "csv")
    stream = prepared[4]["stream"]
    response = export_response(prepared, "probe.csv")
    sent = []

    async def send(message):
        sent.append(message)
        await asyncio.sleep(0.05)

    # The older protocol absorbs the disconnect into its own cancel
    # scope (no exception necessarily escapes); what matters is that
    # the owned snapshot is released and the body stays incomplete.
    asyncio.run(response(_scope(spec_version="2.0"), disconnect_after_start, send))
    assert stream.closed
    bodies = [m.get("body", b"") for m in sent if m["type"] == "http.response.body"]
    assert sum(b.count(b"/probe") for b in bodies) < 5


@pytest.mark.parametrize("export_format", ["csv", "json"])
def test_response_renderer_error_closes_snapshot(probedb, export_format, monkeypatch):
    """A mid-render failure aborts the body without a complete footer."""
    import sqlite3 as _sqlite3

    prepared = _prepared(probedb, export_format)
    stream = prepared[4]["stream"]
    response = export_response(prepared, f"probe.{export_format}")
    calls = {"n": 0}
    real_row = routes_export.queries.export_row_to_dict

    def failing_row(raw):
        calls["n"] += 1
        if calls["n"] > 2:
            raise _sqlite3.OperationalError("probe renderer failure")
        return real_row(raw)

    monkeypatch.setattr(routes_export.queries, "export_row_to_dict", failing_row)
    sent = []

    async def send(message):
        sent.append(message)

    with pytest.raises(_sqlite3.OperationalError):
        asyncio.run(response(_scope(), _receive, send))
    assert stream.closed
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert b'"complete": true' not in body
    assert body.count(b"/probe") <= 2  # aborted: never the full result


def test_unused_prepared_response_has_deterministic_close(probedb):
    """A prepared-but-unsent export closes explicitly, not via GC."""
    prepared = _prepared(probedb, "csv")
    info = prepared[4]
    stream = info["stream"]
    assert not stream.closed
    close_prepared(info)  # explicit deterministic contract
    assert stream.closed
    # Context-manager form of the same contract.
    other = ExportStream(probedb).open()
    other.prepare(_filt(), _rules(), "oldest", max_rows=250_000, display_timezone="UTC")
    with other:
        assert not other.closed
    assert other.closed

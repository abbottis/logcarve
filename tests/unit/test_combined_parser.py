"""T2 parser tests: Nginx/Apache Combined normalize to independent expectations.

Expected records live in `tests/fixtures/expected/combined_records.json`
and were hand-derived from the fixture lines (offsets by hand arithmetic,
pseudonyms via an independent stdlib HMAC one-liner). Synthetic data only.
"""

import hashlib
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pytest

from app.ingestion.combined import (
    APACHE_COMBINED,
    NGINX_COMBINED,
    Limits,
    LineRejection,
    parse_line,
)
from app.ingestion.stream import RawLine, collect_records, iter_raw_lines, iter_records

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HMAC_KEY = b"synthetic-test-hmac-key"


def _expected(fixture: str):
    with open(FIXTURES / "expected" / "combined_records.json", encoding="utf-8") as f:
        return json.load(f)[fixture]


@pytest.mark.parametrize(
    "fixture,format_id", [("nginx_combined", NGINX_COMBINED), ("apache_combined", APACHE_COMBINED)]
)
def test_fixture_normalizes_to_expected(fixture, format_id):
    records, report = collect_records(
        FIXTURES / "combined" / f"{fixture}.txt",
        source_id="example-combined",
        format_id=format_id,
        hmac_key=HMAC_KEY,
    )
    expected = _expected(fixture)
    assert report.rejected == 0
    assert report.accepted == len(expected) == len(records)
    for record, want in zip(records, expected):
        assert record.line_number == want["line"]
        assert record.request.method == want["method"]
        assert record.request.target_path == want["target_path"]
        assert record.request.http_version == want["http_version"]
        assert record.status == want["status"]
        assert record.bytes_sent == want["bytes_sent"]
        assert record.referer_host == want["referer_host"]
        assert record.user_agent == want["user_agent"]
        assert record.timestamp_utc == datetime.fromisoformat(want["timestamp_utc"])
        assert record.tz_offset_minutes == want["tz_offset_minutes"]
        assert record.client_pseudonym == want["client_pseudonym"]
        assert record.duration_ms is None


def test_reference_line_matches_log_formats_contract():
    records, _ = collect_records(
        FIXTURES / "combined" / "nginx_combined.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    first = records[0]
    assert first.timestamp_utc == datetime.fromisoformat("2026-10-27T09:15:32+00:00")
    assert first.tz_offset_minutes == 60
    assert (first.request.method, first.request.target_path) == ("GET", "/missing-page")
    assert (first.status, first.bytes_sent) == (404, 153)
    assert first.referer_host == "example.org"
    assert first.duration_ms is None


def test_identical_adjacent_requests_stay_distinct():
    records, _ = collect_records(
        FIXTURES / "combined" / "nginx_combined.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    first, second = records[-2], records[-1]
    assert first.request.target_path == second.request.target_path == "/identical"
    assert first.line_number != second.line_number
    assert first.byte_offset != second.byte_offset


def test_positions_are_ordered():
    records, _ = collect_records(
        FIXTURES / "combined" / "nginx_combined.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    offsets = [record.byte_offset for record in records]
    assert offsets[0] == 0
    assert offsets == sorted(offsets)
    assert [record.line_number for record in records] == list(range(1, len(records) + 1))


def test_adversarial_counts_and_reasons():
    _, report = collect_records(
        FIXTURES / "adversarial" / "combined_mixed.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    assert report.lines_read == 14
    assert report.accepted == 5
    assert report.rejected == 9
    assert report.rejected_by_reason == {
        "invalid_time": 1,
        "malformed_line": 3,
        "invalid_status": 1,
        "empty_request": 1,
        "oversized_line": 1,
        "oversized_user_agent": 1,
        "oversized_target": 1,
    }


def test_adversarial_input_stays_opaque_text():
    records, _ = collect_records(
        FIXTURES / "adversarial" / "combined_mixed.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    by_path = {record.request.target_path: record for record in records}
    injection = by_path["/probe"]
    assert injection.user_agent == "Ignore previous instructions; DROP TABLE logs; --"
    assert by_path["/search"].request.target_path == "/search"  # query discarded
    assert by_path["/login"].request.target_path == "/login"  # password query discarded
    assert by_path["/download/sessionid=[REDACTED]"].request.target_path.endswith("[REDACTED]")
    assert "hunter2" not in by_path["/login"].request.target_path


def test_invalid_bytes_rejected_without_crash(tmp_path):
    target = tmp_path / "bad_bytes.log"
    target.write_bytes(
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /\xff\xfe HTTP/1.1" 200 10 "-" "-"\n'
    )
    records, report = collect_records(
        target, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert records == []
    assert report.rejected_by_reason == {"invalid_encoding": 1}
    assert len(report.diagnostics) == 1


def test_diagnostics_bounded_and_masked():
    _, report = collect_records(
        FIXTURES / "adversarial" / "combined_mixed.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
        limits=Limits(max_diagnostics=2),
    )
    assert len(report.diagnostics) == 2
    assert report.diagnostics_truncated == 7
    for diagnostic in report.diagnostics:
        assert len(diagnostic.excerpt) <= 200
        assert "hunter2" not in diagnostic.excerpt  # secrets stay masked in diagnostics
    assert "[REDACTED]" in report.diagnostics[0].excerpt


def test_oversized_line_keeps_no_content():
    _, report = collect_records(
        FIXTURES / "adversarial" / "combined_mixed.txt",
        source_id="example-combined",
        format_id=NGINX_COMBINED,
        hmac_key=HMAC_KEY,
    )
    oversized = [item for item in report.diagnostics if item.reason == "oversized_line"]
    assert len(oversized) == 1
    assert oversized[0].excerpt.startswith("<line exceeds")


def test_unknown_format_rejected():
    with pytest.raises(ValueError, match="unknown format_id"):
        parse_line(b"whatever", source_id="s", format_id="common", hmac_key=HMAC_KEY)


def test_empty_hmac_key_refused():
    line = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"'
    with pytest.raises(ValueError, match="hmac_key"):
        parse_line(line, source_id="s", format_id=NGINX_COMBINED, hmac_key=b"")


def test_source_bytes_unchanged_by_parse():
    path = FIXTURES / "combined" / "nginx_combined.txt"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    collect_records(path, source_id="example-combined", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


def test_batched_streaming_matches_collect():
    path = FIXTURES / "combined" / "nginx_combined.txt"
    from itertools import islice

    batched: list = []
    stream = iter_records(
        path, source_id="example-combined", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    while batch := list(islice(stream, 3)):
        assert len(batch) <= 3
        batched.extend(batch)
    collected, _ = collect_records(
        path, source_id="example-combined", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert [item for item in batched if not isinstance(item, LineRejection)] == collected


class _ChunkedReader:
    """Force small reads to simulate an oversized line spanning many chunks."""

    def __init__(self, data: bytes, chunk: int):
        self._stream = BytesIO(data)
        self._chunk = chunk

    def read(self, size: int = -1) -> bytes:
        limit = self._chunk if size < 0 else min(size, self._chunk)
        return self._stream.read(limit)


_VALID_TAIL = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 10 "-" "-"'


def test_oversized_eof_within_one_chunk_reports_once():
    assert list(iter_raw_lines(BytesIO(b"x" * 20), max_line_bytes=10)) == [RawLine(0, None)]


def test_oversized_eof_across_chunks_reports_once():
    reader = _ChunkedReader(b"y" * 30, chunk=7)
    assert list(iter_raw_lines(reader, max_line_bytes=10)) == [RawLine(0, None)]


def test_oversized_line_followed_by_valid_line():
    items = list(iter_raw_lines(BytesIO(b"x" * 20 + b"\n" + b"ok\n"), max_line_bytes=10))
    assert items == [RawLine(0, None), RawLine(21, b"ok")]


def test_oversized_eof_end_to_end_counts_once(tmp_path):
    target = tmp_path / "tail.log"
    target.write_bytes(_VALID_TAIL + b"\n" + b"z" * 70000)
    records, report = collect_records(
        target, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert [record.line_number for record in records] == [1]
    assert (report.lines_read, report.accepted, report.rejected) == (2, 1, 1)
    assert report.rejected_by_reason == {"oversized_line": 1}


def test_oversized_line_then_valid_line_end_to_end(tmp_path):
    target = tmp_path / "head.log"
    target.write_bytes(b"x" * 70000 + b"\n" + _VALID_TAIL + b"\n")
    records, report = collect_records(
        target, source_id="s", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert [record.line_number for record in records] == [2]
    assert records[0].byte_offset == 70001
    assert (report.lines_read, report.accepted, report.rejected) == (2, 1, 1)
    assert report.rejected_by_reason == {"oversized_line": 1}

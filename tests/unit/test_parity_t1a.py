"""T1a parity ingest tests: presets, autodetect, custom mappings, gzip, host filter.

Synthetic fixtures only; the 120-row baseline fixture is untouched.
Expected values below were derived by hand (offsets by byte arithmetic,
pseudonyms via an independent stdlib HMAC one-liner) and pasted in.
"""

import gzip
import hashlib
import json
import math
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

from app.ingestion import gzipio as _gzipio
from app.ingestion.autodetect import (
    AmbiguousFormat,
    UnmatchedFormat,
    detect_lines,
    resolve_format,
)
from app.ingestion.combined import (
    APACHE_COMBINED,
    APACHE_VHOST_COMBINED,
    COMMON,
    NGINX_COMBINED,
    NGINX_EXTENDED,
    CombinedRecord,
    Limits,
    LineRejection,
    TimingInvalid,
    normalize_multi_seconds_to_ms,
    normalize_seconds_to_ms,
    normalize_timing,
    parse_line,
)
from app.ingestion.custom import (
    CUSTOM_MATCH_TIMEOUT_S,
    CustomFormatError,
    load_spec,
    load_spec_file,
    parse_custom_line,
)
from app.ingestion.gzipio import (
    GzipError,
    GzipLimits,
    has_gzip_magic,
    iter_decompressed_chunks,
    logical_fingerprint,
)
from app.ingestion.sources import HostFilter
from app.ingestion.stream import (
    CUSTOM_TIMEOUT_ABORT_STREAK,
    ImportReport,
    collect_records,
    iter_records,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "parity_t1a"
ROOT = FIXTURES.parent.parent
HMAC_KEY = b"parity-t1a-hmac-key"

PSEUDO = {
    "203.0.113.20": "4736b184f52f2125da7425b2791b72253c2cbeed72e078669d6719ee2350fcd4",
    "2001:db8::25": "ab192f87917734b726bd52028176b007509132a8963c31d0bd3eb27d3d4deb8a",
    "198.51.100.7": "c9791da2c8ba62a80c69fc1ae4b8b8a37a99a03f1eb3f585d75f754353fa4ba3",
    "192.0.2.44": "5238db646d134a6b90bf9892f6c1cec96daed00ed21613bc3452ebc89a46c30f",
}


def _gzip_bytes(payload: bytes) -> bytes:
    return gzip.compress(payload, mtime=0)


# --- Common preset ---


def test_common_preset_normalizes():
    records, report = collect_records(
        FIXTURES / "common.txt", source_id="t1a", format_id=COMMON, hmac_key=HMAC_KEY
    )
    assert report.rejected == 0
    assert [record.line_number for record in records] == [1, 2, 3, 4]
    assert [record.byte_offset for record in records] == [0, 83, 179, 259]
    first, second, third, fourth = records
    assert (first.request.method, first.request.target_path) == ("GET", "/missing-page")
    assert first.request.http_version == "HTTP/1.1"
    assert (first.status, first.bytes_sent) == (404, 153)
    assert first.referer_host is None and first.user_agent is None
    assert first.timestamp_utc == datetime.fromisoformat("2026-10-27T09:15:32+00:00")
    assert first.tz_offset_minutes == 60
    assert first.client_pseudonym == PSEUDO["203.0.113.20"]
    assert first.duration_ms is None
    # IPv6 + query discard.
    assert second.client_pseudonym == PSEUDO["2001:db8::25"]
    assert second.request.target_path == "/search"
    # Missing "-" bytes stay None; HTTP/2 retained.
    assert third.bytes_sent == 128
    assert third.request.http_version == "HTTP/2"
    # No-version request keeps version None; "-" size stays None.
    assert fourth.request.http_version is None
    assert fourth.bytes_sent is None
    assert fourth.tz_offset_minutes == -240


def test_common_never_confused_with_combined():
    raw = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"'
    assert isinstance(
        parse_line(raw, source_id="s", format_id=COMMON, hmac_key=HMAC_KEY), LineRejection
    )
    assert isinstance(
        parse_line(
            b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10',
            source_id="s",
            format_id=NGINX_COMBINED,
            hmac_key=HMAC_KEY,
        ),
        LineRejection,
    )


# --- Apache vhost preset ---


def test_apache_vhost_preset_and_escapes():
    records, report = collect_records(
        FIXTURES / "apache_vhost.txt",
        source_id="t1a",
        format_id=APACHE_VHOST_COMBINED,
        hmac_key=HMAC_KEY,
    )
    assert report.rejected == 0
    assert [record.byte_offset for record in records] == [0, 125, 260]
    first, second, third = records
    assert first.extra.server_host == "example.org"
    assert first.request.target_path == "/start"
    assert first.referer_host == "example.org"
    # Apache backslash escapes resolve; pseudonym covers the client, not the vhost.
    assert second.request.target_path == '/q="logcarve"'
    assert second.client_pseudonym == PSEUDO["2001:db8::25"]
    assert third.extra.server_host == "other.example"


# --- Nginx Extended preset ---


def test_nginx_extended_measurements():
    records, report = collect_records(
        FIXTURES / "nginx_extended.txt",
        source_id="t1a",
        format_id=NGINX_EXTENDED,
        hmac_key=HMAC_KEY,
    )
    assert report.rejected == 0
    full, mime_line, nulls = records
    assert full.extra.server_host == "example.org"
    assert full.extra.cache_status == "MISS"
    assert full.extra.request_time_ms == pytest.approx(123.0)
    # Multi-value upstream sums explicitly with a component count.
    assert full.extra.upstream_time_ms == pytest.approx(120.0)
    assert full.extra.upstream_count == 2
    assert full.extra.mime_type == "text/html"
    assert full.extra.tls_protocol == "TLSv1.3"
    assert full.extra.referer_scheme == "https"
    assert full.extra.referer_path == "/old"
    # Charset parameters normalize to the media type; "-" upstream stays None.
    assert mime_line.extra.mime_type == "text/css"
    assert mime_line.extra.request_time_ms == pytest.approx(2.0)
    assert mime_line.extra.upstream_time_ms is None
    assert mime_line.client_pseudonym == PSEUDO["2001:db8::25"]
    # Null row: absent stays None, never zero (including the "-" host).
    assert nulls.extra.server_host is None
    assert nulls.extra.cache_status is None
    assert nulls.extra.request_time_ms is None
    assert nulls.extra.upstream_time_ms is None
    assert nulls.extra.mime_type is None
    assert nulls.extra.tls_protocol is None
    assert nulls.user_agent is None


def test_nginx_extended_approved_trailing_host_fixture():
    """Approved LogWerk NginxExtended order: Combined, then six trailing fields."""
    raw = (
        b'192.0.2.1 - - [27/Oct/2026:10:15:00 +0000] "GET / HTTP/1.1" 200 10 '
        b'"-" "Example/1.0" example.org HIT 0.123 text/html; charset=utf-8 TLSv1.3 "0.100"'
    )
    item = parse_line(raw, source_id="s", format_id=NGINX_EXTENDED, hmac_key=HMAC_KEY)
    assert isinstance(item, CombinedRecord)
    assert item.extra.server_host == "example.org"
    assert item.extra.cache_status == "HIT"
    assert item.extra.request_time_ms == pytest.approx(123.0)
    # MIME with "; charset=..." keeps the media type without shifting TLS/upstream.
    assert item.extra.mime_type == "text/html"
    assert item.extra.tls_protocol == "TLSv1.3"
    assert item.extra.upstream_time_ms == pytest.approx(100.0)
    assert item.extra.upstream_count == 1


@pytest.mark.parametrize(
    "line,reason",
    [
        (
            (
                b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" example.org MISS fast text/html TLSv1.3 "-"'
            ),
            "invalid_timing",
        ),
        (
            (
                b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" example.org MISS 0.1 text/html TLSv1.3 "0.1, soon"'
            ),
            "invalid_timing",
        ),
        (
            (
                b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" example.org MISS 0.1 not-a-mime TLSv1.3 "-"'
            ),
            "invalid_mime",
        ),
        (
            (
                b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" example.org MISS 0.1 text/html "tls 1.3" "-"'
            ),
            "malformed_line",
        ),
        (
            # A leading vhost is Apache vhost Combined, never this preset.
            (
                b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" MISS 0.1 text/html TLSv1.3 "-"'
            ),
            "malformed_line",
        ),
    ],
)
def test_nginx_extended_invalid_values_reject_explicitly(line, reason):
    item = parse_line(line, source_id="s", format_id=NGINX_EXTENDED, hmac_key=HMAC_KEY)
    assert isinstance(item, LineRejection)
    assert item.reason == reason


# --- Autodetect ---


def test_autodetect_names_each_preset():
    assert (
        detect_lines((FIXTURES / "nginx_extended.txt").read_bytes().split(b"\n")).format_id
        == NGINX_EXTENDED
    )
    assert (
        detect_lines((FIXTURES / "apache_vhost.txt").read_bytes().split(b"\n")).format_id
        == APACHE_VHOST_COMBINED
    )
    assert detect_lines((FIXTURES / "common.txt").read_bytes().split(b"\n")).format_id == COMMON


def test_autodetect_combined_twins_resolve_to_default(tmp_path):
    """The Combined family shares one grammar: no override needed per file.

    Sampling cannot infer server software, so the twins resolve to the
    configured flavor while both candidates stay reported honestly.
    """
    raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"\n'
        b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /y HTTP/1.1" 200 5 "-" "-"\n'
    )
    result = detect_lines(raw.split(b"\n"))
    assert result.ambiguous is False
    assert result.format_id == NGINX_COMBINED
    assert set(result.candidates) == {"nginx_combined", "apache_combined"}
    assert result.confidence == pytest.approx(1.0)
    apache_result = detect_lines(raw.split(b"\n"), default_combined=APACHE_COMBINED)
    assert apache_result.ambiguous is False
    assert apache_result.format_id == APACHE_COMBINED
    assert set(apache_result.candidates) == {"nginx_combined", "apache_combined"}
    target = tmp_path / "twins.log"
    target.write_bytes(raw)
    assert resolve_format("auto", target, limits=Limits()) == NGINX_COMBINED
    assert (
        resolve_format("auto", target, limits=Limits(), default_combined=APACHE_COMBINED)
        == APACHE_COMBINED
    )


def test_autodetect_mixed_formats_fail_closed(tmp_path):
    """Genuinely different formats in one sample still fail closed."""
    raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"\n'
        b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /y HTTP/1.1" 200 5\n'
    )
    result = detect_lines(raw.split(b"\n"))
    assert result.ambiguous is True
    assert result.format_id is None
    target = tmp_path / "mixed.log"
    target.write_bytes(raw)
    with pytest.raises(AmbiguousFormat):
        resolve_format("auto", target, limits=Limits())


def test_autodetect_rejects_bad_sample_size_and_default():
    raw = [b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"']
    for bad in (0, -1, 1025, True, "32", float("nan")):
        with pytest.raises(ValueError):
            detect_lines(raw, sample_lines=bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        detect_lines(raw, default_combined="common")  # type: ignore[arg-type]


def test_autodetect_unmatched_and_resolve_passthrough(tmp_path):
    with pytest.raises(UnmatchedFormat):
        detect_lines([b"definitely not a log line", b"neither is this"])
    target = tmp_path / "x.log"
    target.write_bytes(b"whatever")
    assert resolve_format(NGINX_COMBINED, target) == NGINX_COMBINED


def test_autodetect_escape_prefers_apache():
    raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /q=\\"x\\" HTTP/1.1" 200 10 "-" "-"\n'
        b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /y HTTP/1.1" 200 5 "-" "-"\n'
    )
    assert detect_lines(raw.split(b"\n")).format_id == "apache_combined"


# --- Custom mappings ---


def test_custom_valid_us_timing_and_minimization():
    spec = load_spec_file(FIXTURES / "custom_acme.json")
    records, report = collect_records(
        FIXTURES / "custom_acme.txt",
        source_id="t1a",
        format_id="custom",
        hmac_key=HMAC_KEY,
        custom_format=spec,
    )
    assert report.rejected == 0
    first, second = records
    assert first.format_id == "custom-acme"
    # Microseconds normalize to milliseconds; query values discarded.
    assert first.extra.request_time_ms == pytest.approx(1.5)
    assert first.request.target_path == "/custom"
    assert "hunter2" not in first.request.target_path
    assert first.extra.referer_path == "/app"
    assert second.extra.request_time_ms is None


def test_custom_specs_rejected_at_validation():
    good_pattern = (
        r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
        r" (?P<status>\d{3}) (?P<size>\d+|-)$"
    )

    def make(**overrides):
        base = {"format_id": "custom-ok", "pattern": good_pattern}
        base.update(overrides)
        return base

    load_spec(make())  # sanity: the base shape validates
    bad_id = make(format_id="acme")
    with pytest.raises(CustomFormatError):
        load_spec(bad_id)
    missing_group = make(pattern=r"^(?P<host>\S+) (?P<status>\d{3})$")
    with pytest.raises(CustomFormatError):
        load_spec(missing_group)
    rogue_group = make(
        pattern=good_pattern.replace("(?P<size>", "(?P<injected>").replace(
            "(?P<status>", "(?P<status>"
        )
    )
    assert "injected" in rogue_group["pattern"]
    with pytest.raises(CustomFormatError):
        load_spec(rogue_group)
    evil = make(
        pattern=r"^(?P<host>(\S+)+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
        r" (?P<status>\d{3}) (?P<size>\d+|-)$"
    )
    with pytest.raises(CustomFormatError):
        load_spec(evil)
    catastrophic = make(
        pattern=r"^(?P<host>\S+) \[(?P<time>.*.*)\] \"(?P<request>[^\"]*)\""
        r" (?P<status>\d{3}) (?P<size>\d+|-)$"
    )
    with pytest.raises(CustomFormatError):
        load_spec(catastrophic)
    bad_unit = make(timing={"request_time": {"unit": "fortnights"}})
    with pytest.raises(CustomFormatError):
        load_spec(bad_unit)
    unknown_timing_field = make(timing={"bytes_sent": {"unit": "s"}})
    with pytest.raises(CustomFormatError):
        load_spec(unknown_timing_field)
    with pytest.raises(CustomFormatError):
        load_spec({"format_id": "custom-ok"})


def test_custom_runtime_budget_bounded(tmp_path):
    spec = load_spec_file(FIXTURES / "custom_acme.json")
    evil_line = b"203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] " + b"A" * 70000 + b"\n"
    target = tmp_path / "evil.log"
    target.write_bytes(evil_line)
    _, report = collect_records(
        target, source_id="s", format_id="custom", hmac_key=HMAC_KEY, custom_format=spec
    )
    assert report.rejected_by_reason == {"oversized_line": 1}


# --- gzip ---


def test_gzip_magic_detection_ignores_extension(tmp_path):
    payload = (FIXTURES / "common.txt").read_bytes()
    misnamed = tmp_path / "access.log"  # no .gz suffix, still gzip bytes
    misnamed.write_bytes(_gzip_bytes(payload))
    assert has_gzip_magic(misnamed) is True
    records, report = collect_records(
        misnamed, source_id="t1a", format_id=COMMON, hmac_key=HMAC_KEY
    )
    assert report.is_gzip is True
    assert report.gzip_members == 1
    assert [record.byte_offset for record in records] == [0, 83, 179, 259]
    assert records[0].request.target_path == "/missing-page"
    assert report.rejected == 0


def test_plain_behavior_stable_and_source_untouched(tmp_path):
    target = tmp_path / "plain.log"
    target.write_bytes((FIXTURES / "common.txt").read_bytes())
    assert has_gzip_magic(target) is False
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    records, report = collect_records(target, source_id="t1a", format_id=COMMON, hmac_key=HMAC_KEY)
    assert report.is_gzip is False
    assert len(records) == 4
    assert hashlib.sha256(target.read_bytes()).hexdigest() == before
    assert report.consumed_sha256 == before


def test_gzip_concatenated_members_decode_in_order(tmp_path):
    first = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /one HTTP/1.1" 200 1 "-" "-"\n'
    second = b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /two HTTP/1.1" 200 2 "-" "-"\n'
    target = tmp_path / "multi.gz"
    target.write_bytes(_gzip_bytes(first) + _gzip_bytes(second))
    records, report = collect_records(
        target, source_id="t1a", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert report.gzip_members == 2
    assert [record.request.target_path for record in records] == ["/one", "/two"]
    assert [record.byte_offset for record in records] == [0, len(first)]


@pytest.mark.parametrize("read_size", [1, 7, 31, 65536])
@pytest.mark.parametrize("output_cap", [1, 17, 65536])
def test_gzip_member_boundary_single_remainder(tmp_path, monkeypatch, read_size, output_cap):
    """One remainder at end-of-member: tail/unused duplicates must not rescore.

    On some interpreters a max_length-capped call that finishes a member
    reports the next member's bytes in BOTH unconsumed_tail and unused_data.
    Concatenating both decodes the next member twice and inflates the member
    count (this exact shape raised gzip_member_limit instead of yielding 42
    bytes). The eof remainder is unused_data alone.
    """
    monkeypatch.setattr(_gzipio, "_CHUNK_SIZE", read_size)
    monkeypatch.setattr(_gzipio, "_OUTPUT_CAP", output_cap)
    expected = b"A" * 19 + b"B" * 23
    target = tmp_path / "two.gz"
    target.write_bytes(_gzip_bytes(b"A" * 19) + _gzip_bytes(b"B" * 23))
    chunks, stats = iter_decompressed_chunks(
        target,
        limits=GzipLimits(max_gzip_members=3, max_uncompressed_bytes=1000),
    )
    assert b"".join(chunks) == expected
    assert stats["members"] == 2
    assert stats["logical_bytes"] == len(expected)
    # Exactly at the member limit still passes; one member fewer fails.
    exact, exact_stats = iter_decompressed_chunks(
        target,
        limits=GzipLimits(max_gzip_members=2, max_uncompressed_bytes=1000),
    )
    assert b"".join(exact) == expected
    assert exact_stats["members"] == 2
    tight, _ = iter_decompressed_chunks(
        target, limits=GzipLimits(max_gzip_members=1, max_uncompressed_bytes=1000)
    )
    with pytest.raises(GzipError) as excinfo:
        b"".join(tight)
    assert excinfo.value.code == "interrupted:gzip_member_limit"


def test_gzip_truncated_and_crc_fail_fixed_codes(tmp_path):
    payload = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /one HTTP/1.1" 200 1 "-" "-"\n'
    blob = bytearray(_gzip_bytes(payload))
    truncated = tmp_path / "cut.gz"
    truncated.write_bytes(bytes(blob[: len(blob) // 2]))
    with pytest.raises(GzipError) as excinfo:
        logical_fingerprint(truncated)
    assert excinfo.value.code == "interrupted:gzip_truncated"
    crc_broken = tmp_path / "crc.gz"
    damaged = bytearray(blob)
    damaged[-8] ^= 0xFF  # flip a stored-CRC byte, keep the header valid
    crc_broken.write_bytes(bytes(damaged))
    with pytest.raises(GzipError) as excinfo:
        logical_fingerprint(crc_broken)
    assert excinfo.value.code == "interrupted:gzip_crc_error"


def test_gzip_bounds_reject_zipbomb_and_member_flood(tmp_path):
    bomb = _gzip_bytes(b"A" * 1_000_000 + b"\n")
    target = tmp_path / "bomb.gz"
    target.write_bytes(bomb)
    tiny = GzipLimits(
        max_compressed_bytes=10_000_000,
        max_uncompressed_bytes=10_000,
        max_compression_ratio=10.0,
        max_gzip_members=64,
    )
    with pytest.raises(GzipError) as excinfo:
        logical_fingerprint(target, limits=tiny)
    assert excinfo.value.code in ("interrupted:gzip_too_large", "interrupted:gzip_ratio_exceeded")
    # The ratio guard ignores tiny inputs by design (floor): the same
    # bomb passes untouched under default limits.
    relaxed = GzipLimits(
        max_compressed_bytes=10_000_000,
        max_uncompressed_bytes=10_000_000,
        max_compression_ratio=10.0,
        max_gzip_members=64,
    )
    assert logical_fingerprint(target, limits=relaxed).logical_size == 1_000_001
    # With the floor out of the way the same input breaches the ratio.
    from app.ingestion import gzipio

    old_floor = gzipio._RATIO_FLOOR_BYTES
    gzipio._RATIO_FLOOR_BYTES = 0
    try:
        with pytest.raises(GzipError) as excinfo:
            logical_fingerprint(target, limits=relaxed)
    finally:
        gzipio._RATIO_FLOOR_BYTES = old_floor
    assert excinfo.value.code == "interrupted:gzip_ratio_exceeded"
    line = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /m HTTP/1.1" 200 1 "-" "-"\n'
    flooded = tmp_path / "flood.gz"
    flooded.write_bytes(_gzip_bytes(line) * 3)
    with pytest.raises(GzipError) as excinfo:
        logical_fingerprint(flooded, limits=GzipLimits(max_gzip_members=2))
    assert excinfo.value.code == "interrupted:gzip_member_limit"


def test_gzip_oversize_line_counts_once_with_offsets(tmp_path):
    good = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 1 "-" "-"\n'
    target = tmp_path / "mixed.gz"
    target.write_bytes(_gzip_bytes(good + b"y" * 70000 + b"\n" + good))
    records, report = collect_records(
        target, source_id="t1a", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY
    )
    assert [record.line_number for record in records] == [1, 3]
    assert records[1].byte_offset == len(good) + 70001
    assert (report.lines_read, report.accepted, report.rejected) == (3, 2, 1)
    assert report.rejected_by_reason == {"oversized_line": 1}


def test_gzip_digest_covers_every_logical_byte(tmp_path):
    payload = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 1 "-" "-"\n'
        b"broken line without quotes\n"
    )
    target = tmp_path / "dirty.gz"
    target.write_bytes(_gzip_bytes(payload))
    report = ImportReport(source_id="t1a", format_id=NGINX_COMBINED)
    list(
        iter_records(
            target, source_id="t1a", format_id=NGINX_COMBINED, hmac_key=HMAC_KEY, report=report
        )
    )
    assert report.rejected == 1
    assert report.consumed_sha256 == hashlib.sha256(payload).hexdigest()


def test_import_never_reads_whole_file(tmp_path, monkeypatch):
    from pathlib import Path as RealPath

    target = tmp_path / "big.gz"
    target.write_bytes(_gzip_bytes(b"x" * 100 + b"\n"))
    monkeypatch.setattr(
        RealPath, "read_bytes", lambda self: (_ for _ in ()).throw(AssertionError("full read"))
    )
    monkeypatch.setattr(
        RealPath,
        "read_text",
        lambda self, *a, **k: (_ for _ in ()).throw(AssertionError("full read")),
    )
    _, report = collect_records(target, source_id="t1a", format_id=COMMON, hmac_key=HMAC_KEY)
    assert report.lines_read == 1


# --- Host filter ---


def test_host_filter_isolates_counts():
    records, report = collect_records(
        FIXTURES / "apache_vhost.txt",
        source_id="t1a",
        format_id=APACHE_VHOST_COMBINED,
        hmac_key=HMAC_KEY,
        host_filter=HostFilter(["example.org"]),
    )
    assert [record.request.target_path for record in records] == ["/start", '/q="logcarve"']
    assert (report.lines_read, report.accepted, report.rejected, report.foreign_skipped) == (
        3,
        2,
        0,
        1,
    )
    assert len(report.skipped_hosts) == 1
    # Skipped foreign hosts are withheld: a logged host can itself be an
    # address, so only counts plus line/offset positions are diagnostic.
    assert report.skipped_hosts[0].host == "<withheld>"
    assert report.skipped_hosts[0].line_number == 3
    # No filter: host-bearing lines pass through (documented, counted as accepted).
    _, open_report = collect_records(
        FIXTURES / "apache_vhost.txt",
        source_id="t1a",
        format_id=APACHE_VHOST_COMBINED,
        hmac_key=HMAC_KEY,
    )
    assert (open_report.accepted, open_report.foreign_skipped) == (3, 0)


def test_host_filter_never_matches_foreign_case_insensitively():
    assert HostFilter(["Example.ORG"]).matches("example.org") is True
    assert HostFilter(["example.org"]).matches("other.example") is False
    # Lines without host information always pass through.
    assert HostFilter(["example.org"]).matches(None) is True
    with pytest.raises(ValueError):
        HostFilter([])


# --- Custom regex engine timeout ---

EVIL_TRAILING_PATTERN = (
    r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
    r" (?P<status>\d{3}) (?P<size>\d+|-) (?:a|aa)+$"
)
EVIL_TRAILING_LINE = (
    b'203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 ' + b"a" * 45 + b"!"
)


def _evil_spec():
    # The static allowlists only cover named-group bodies, so this
    # ambiguity *outside* any group validates: the runtime engine
    # deadline is the real guarantee, not a static proof.
    return load_spec({"format_id": "custom-adv", "pattern": EVIL_TRAILING_PATTERN})


def test_custom_outside_group_ambiguity_aborts_with_fixed_code():
    spec = _evil_spec()
    started = time.time()
    item = parse_custom_line(EVIL_TRAILING_LINE, spec=spec, source_id="s", hmac_key=HMAC_KEY)
    elapsed = time.time() - started
    assert isinstance(item, LineRejection)
    assert item.reason == "custom_timeout"
    # The engine deadline fired (it waited out the budget) without hanging
    # and without leaking engine text into the rejection.
    assert CUSTOM_MATCH_TIMEOUT_S - 0.1 <= elapsed < 15
    assert "Timeout" not in item.excerpt


def test_custom_timeout_fires_in_isolated_subprocess(tmp_path):
    """Hard-kill failsafe: a hung match can never stall the suite."""
    script = tmp_path / "evil_match.py"
    script.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from app.ingestion.custom import load_spec, parse_custom_line\n"
        f"spec = load_spec({{'format_id': 'custom-adv', 'pattern': {EVIL_TRAILING_PATTERN!r}}})\n"
        f"line = {EVIL_TRAILING_LINE!r}\n"
        "item = parse_custom_line(line, spec=spec, source_id='s', hmac_key=b'k')\n"
        "print(type(item).__name__ + ':' + item.reason)\n"
    )
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "LineRejection:custom_timeout"


# --- Custom spec size/type validation ---


def test_custom_spec_size_and_type_validation(tmp_path):
    good_pattern = (
        r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
        r" (?P<status>\d{3}) (?P<size>\d+|-)$"
    )

    def make(**overrides):
        base = {"format_id": "custom-ok", "pattern": good_pattern}
        base.update(overrides)
        return base

    # Wrong JSON types fail closed instead of coercing a cap into existence.
    for bad_cap in ("2048", 20.5, True, ["2048"], {"n": 2048}, None):
        with pytest.raises(CustomFormatError):
            load_spec(make(max_pattern_len=bad_cap))
    defaulted = load_spec(make())
    assert defaulted.format_id == "custom-ok"
    assert defaulted.pattern.pattern == load_spec(make(max_pattern_len=2048)).pattern.pattern
    # Zero and negative caps fail closed.
    for bad_cap in (0, -5):
        with pytest.raises(CustomFormatError):
            load_spec(make(max_pattern_len=bad_cap))
    # A huge cap is safely clamped by the absolute ceiling, not a bypass.
    assert load_spec(make(max_pattern_len=2**70)).format_id == "custom-ok"
    # A pattern longer than the configured cap is rejected, not truncated.
    with pytest.raises(CustomFormatError):
        load_spec(make(max_pattern_len=10))
    assert load_spec(make(max_pattern_len=len(good_pattern))).format_id == "custom-ok"
    # Unknown time formats fail closed with a fixed code.
    with pytest.raises(CustomFormatError):
        load_spec(make(time_format="apache"))
    # Oversize files are rejected after one bounded read, never buffered.
    oversize = tmp_path / "big.json"
    oversize.write_bytes(b" " * (65536 + 1))
    with pytest.raises(CustomFormatError):
        load_spec_file(oversize)
    not_json = tmp_path / "nope.json"
    not_json.write_bytes(b"{definitely not json")
    with pytest.raises(CustomFormatError):
        load_spec_file(not_json)
    as_list = tmp_path / "list.json"
    as_list.write_bytes(b"[1, 2]")
    with pytest.raises(CustomFormatError):
        load_spec_file(as_list)
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe{\xff")
    with pytest.raises(CustomFormatError):
        load_spec_file(binary)


# --- Timing: finite, nonnegative, serializable ---


def test_timing_rejects_negative_nonfinite_and_malformed():
    assert normalize_seconds_to_ms("0.123") == pytest.approx(123.0)
    assert normalize_seconds_to_ms("0") == 0.0  # measured zero stays a valid zero
    assert normalize_seconds_to_ms("-") is None
    for bad in ("-1", "-0.001", "nan", "NaN", "inf", "-inf", "Infinity", "1e3", "", "abc"):
        with pytest.raises(TimingInvalid):
            normalize_seconds_to_ms(bad)
    # A 400-digit number overflows to infinity and rejects instead of persisting inf.
    with pytest.raises(TimingInvalid):
        normalize_seconds_to_ms("9" * 400)
    # Aggregate overflow across individually finite components also rejects.
    huge_part = "1" + "7" * 305  # ~1.7e305 s -> ~1.7e308 ms, still finite
    assert math.isfinite(float(huge_part) * 1000.0)
    with pytest.raises(TimingInvalid):
        normalize_multi_seconds_to_ms(f"{huge_part}, {huge_part}")
    with pytest.raises(TimingInvalid):
        normalize_multi_seconds_to_ms("-1, 0.2")
    # Absent upstream timing infers no component count: (None, None),
    # so legacy rows keep NULL instead of a fabricated zero.
    assert normalize_multi_seconds_to_ms("-") == (None, None)
    assert normalize_multi_seconds_to_ms("0.100") == (pytest.approx(100.0), 1)


def test_timing_units_zero_and_mime_cache_serialization():
    assert normalize_timing("1500", "us") == pytest.approx(1.5)
    assert normalize_timing("2.5", "ms") == pytest.approx(2.5)
    assert normalize_timing("0", "s") == 0.0
    assert normalize_timing("-", "us") is None
    for bad_value, unit in (("-5", "ms"), ("-0.5", "s"), ("nan", "ms"), ("3", "fortnights")):
        with pytest.raises(TimingInvalid):
            normalize_timing(bad_value, unit)
    # Lowercase cache normalizes up; every timing output stays JSON-safe.
    raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
        b' 200 1 "-" "-" example.org hit 0.010 text/html TLSv1.3 "0.001"'
    )
    item = parse_line(raw, source_id="s", format_id=NGINX_EXTENDED, hmac_key=HMAC_KEY)
    assert isinstance(item, CombinedRecord)
    assert item.extra.cache_status == "HIT"
    assert item.extra.request_time_ms == pytest.approx(10.0)
    assert item.extra.upstream_time_ms == pytest.approx(1.0)
    values = [item.extra.request_time_ms, item.extra.upstream_time_ms]
    assert all(value is None or math.isfinite(value) for value in values)
    assert json.loads(json.dumps(values)) == values


# --- Gzip: fixed allocation, identical bytes/digests ---


def test_gzip_bounded_allocation_many_small_chunks(tmp_path, monkeypatch):
    """Every decompress() call carries a positive max_length.

    With a 17-byte output cap a 5001-byte payload must arrive as hundreds
    of tiny chunks (never one 5001-byte C allocation) with byte-identical
    output and a matching logical digest.
    """
    from app.ingestion import gzipio as _gzipio_mod

    monkeypatch.setattr(_gzipio_mod, "_OUTPUT_CAP", 17)
    payload = b"x" * 5000 + b"\n"
    target = tmp_path / "steady.gz"
    target.write_bytes(_gzip_bytes(payload))
    chunks, stats = iter_decompressed_chunks(target, limits=GzipLimits())
    pieces = list(chunks)
    assert len(pieces) > 100
    assert all(len(piece) <= 17 for piece in pieces)
    assert b"".join(pieces) == payload
    assert stats["logical_bytes"] == len(payload)
    assert stats["members"] == 1
    assert logical_fingerprint(target).logical_sha256 == hashlib.sha256(payload).hexdigest()


# --- Resource/sample limit validation ---


def test_limits_reject_nonfinite_negative_absurd():
    for kwargs in (
        {"max_compressed_bytes": 0},
        {"max_compressed_bytes": -1},
        {"max_compressed_bytes": True},
        {"max_compressed_bytes": "100"},
        {"max_compressed_bytes": 2**63},
        {"max_uncompressed_bytes": 0},
        {"max_compression_ratio": float("nan")},
        {"max_compression_ratio": float("inf")},
        {"max_compression_ratio": 0.5},
        {"max_compression_ratio": True},
        {"max_compression_ratio": 10**9},
        {"max_gzip_members": 0},
        {"max_gzip_members": -3},
        {"max_gzip_members": 10**9},
        {"max_gzip_members": False},
    ):
        with pytest.raises(ValueError):
            GzipLimits(**kwargs)
    for kwargs in (
        {"max_line_bytes": 0},
        {"max_line_bytes": -1},
        {"max_line_bytes": True},
        {"max_line_bytes": 2**27},
        {"max_diagnostics": -1},
        {"max_diagnostics": 10**9},
        {"max_target_len": "100"},
    ):
        with pytest.raises(ValueError):
            Limits(**kwargs)
    assert Limits(max_diagnostics=0).max_diagnostics == 0


def test_iter_records_rejects_bad_sample_size(tmp_path):
    target = tmp_path / "x.log"
    target.write_bytes(b"whatever\n")
    for bad in (0, -1, 1025, True, "32"):
        with pytest.raises(ValueError):
            list(
                iter_records(
                    target,
                    source_id="s",
                    format_id=NGINX_COMBINED,
                    hmac_key=HMAC_KEY,
                    autodetect_sample_lines=bad,
                )
            )
    with pytest.raises(ValueError):
        list(
            iter_records(
                target,
                source_id="s",
                format_id=NGINX_COMBINED,
                hmac_key=HMAC_KEY,
                default_combined="common",
            )
        )


# --- Custom timeout abuse aborts honestly ---


def test_custom_timeout_abuse_aborts_import(tmp_path, monkeypatch):
    import app.ingestion.custom as _custom_mod

    monkeypatch.setattr(_custom_mod, "CUSTOM_MATCH_TIMEOUT_S", 0.05)
    spec = _evil_spec()
    lines = [EVIL_TRAILING_LINE] * (CUSTOM_TIMEOUT_ABORT_STREAK + 4)
    target = tmp_path / "evil.log"
    target.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(CustomFormatError) as excinfo:
        list(
            iter_records(
                target, source_id="s", format_id="custom", hmac_key=HMAC_KEY, custom_format=spec
            )
        )
    assert excinfo.value.code == "interrupted:custom_timeout"


def test_custom_timeout_streak_resets_on_success(tmp_path, monkeypatch):
    import app.ingestion.custom as _custom_mod

    monkeypatch.setattr(_custom_mod, "CUSTOM_MATCH_TIMEOUT_S", 0.05)
    spec = _evil_spec()
    good = b'203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /ok HTTP/1.1" 200 10 ' + b"a" * 45
    lines = [EVIL_TRAILING_LINE, good] * 8
    target = tmp_path / "mixed.log"
    target.write_bytes(b"\n".join(lines) + b"\n")
    report = ImportReport(source_id="s", format_id="custom")
    items = list(
        iter_records(
            target,
            source_id="s",
            format_id="custom",
            hmac_key=HMAC_KEY,
            report=report,
            custom_format=spec,
        )
    )
    assert report.rejected == 8
    assert report.rejected_by_reason == {"custom_timeout": 8}
    assert sum(isinstance(item, CombinedRecord) for item in items) == 8


# --- Custom vhost "-" marker ---


def test_custom_vhost_dash_marker_passes_filter():
    spec = load_spec_file(FIXTURES / "custom_vhost.json")
    raw = b'- 203.0.113.20 [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10'
    item = parse_custom_line(raw, spec=spec, source_id="s", hmac_key=HMAC_KEY)
    assert isinstance(item, CombinedRecord)
    assert item.extra.server_host is None
    assert HostFilter(["example.org"]).matches(item.extra.server_host) is True

"""T1a parity ingest tests: presets, autodetect, custom mappings, gzip, host filter.

Synthetic fixtures only; the 120-row baseline fixture is untouched.
Expected values below were derived by hand (offsets by byte arithmetic,
pseudonyms via an independent stdlib HMAC one-liner) and pasted in.
"""

import gzip
import hashlib
from datetime import datetime
from pathlib import Path

import pytest

from app.ingestion.autodetect import (
    AmbiguousFormat,
    UnmatchedFormat,
    detect_lines,
    resolve_format,
)
from app.ingestion.combined import (
    APACHE_VHOST_COMBINED,
    COMMON,
    NGINX_COMBINED,
    NGINX_EXTENDED,
    Limits,
    LineRejection,
    parse_line,
)
from app.ingestion.custom import CustomFormatError, load_spec, load_spec_file
from app.ingestion.gzipio import (
    GzipError,
    GzipLimits,
    has_gzip_magic,
    logical_fingerprint,
)
from app.ingestion.sources import HostFilter
from app.ingestion.stream import ImportReport, collect_records, iter_records

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "parity_t1a"
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
    # Null row: absent stays None, never zero.
    assert nulls.extra.cache_status is None
    assert nulls.extra.request_time_ms is None
    assert nulls.extra.upstream_time_ms is None
    assert nulls.extra.mime_type is None
    assert nulls.extra.tls_protocol is None
    assert nulls.user_agent is None


@pytest.mark.parametrize(
    "line,reason",
    [
        (
            (
                b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" MISS fast text/html TLSv1.3 "-"'
            ),
            "invalid_timing",
        ),
        (
            (
                b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" MISS 0.1 text/html TLSv1.3 "0.1, soon"'
            ),
            "invalid_timing",
        ),
        (
            (
                b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" MISS 0.1 not-a-mime TLSv1.3 "-"'
            ),
            "invalid_mime",
        ),
        (
            (
                b'example.org 203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1"'
                b' 200 1 "-" "-" MISS 0.1 text/html "tls 1.3" "-"'
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


def test_autodetect_combined_twins_fail_closed(tmp_path):
    raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 10 "-" "-"\n'
        b'198.51.100.7 - - [27/Oct/2026:10:16:00 +0100] "GET /y HTTP/1.1" 200 5 "-" "-"\n'
    )
    result = detect_lines(raw.split(b"\n"))
    assert result.ambiguous is True
    assert set(result.candidates) == {"nginx_combined", "apache_combined"}
    target = tmp_path / "twins.log"
    target.write_bytes(raw)
    with pytest.raises(AmbiguousFormat):
        resolve_format("auto", target, limits=Limits())


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
    assert report.skipped_hosts[0].host == "other.example"
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

"""T5b1 parity ingestion tests: declared custom timestamp modes and int64 byte domain.

Synthetic fixtures only. Expected values below were derived by hand
(offsets by arithmetic, epoch values via an independent ``datetime``
construction, pseudonyms untouched) and pasted in.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.ingestion.combined import (
    APACHE_COMBINED,
    APACHE_VHOST_COMBINED,
    COMBINED_TIME,
    COMMON,
    MAX_BYTES_VALUE,
    NGINX_COMBINED,
    NGINX_EXTENDED,
    _normalize_time_with_mode,
    enrichment_policy,
    normalize_bytes_value,
    parse_line,
)
from app.ingestion.custom import CustomFormatError, load_spec, parse_custom_line
from app.ingestion.stream import collect_records

HMAC_KEY = b"parity-t5b1-hmac-key"

PATTERN = (
    r"^(?P<host>\S+) \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\""
    r" (?P<status>\d{3}) (?P<size>\d+|-)$"
)


def make_spec(**overrides):
    base = {"format_id": "custom-t5b1", "pattern": PATTERN}
    base.update(overrides)
    return load_spec(base)


def custom_line(time, size="128", host="203.0.113.20"):
    return f'{host} [{time}] "GET /item HTTP/1.1" 200 {size}'.encode()


def parse_custom(time, size="128", **overrides):
    spec = make_spec(**overrides)
    return parse_custom_line(
        custom_line(time, size),
        spec=spec,
        source_id="s",
        hmac_key=HMAC_KEY,
        line_number=1,
    )


# --- Spec validation ---


def test_time_format_modes_accepted_and_unknown_rejected():
    assert make_spec().time_format == "combined"
    for mode in ("combined", "iso8601", "epoch_s", "epoch_ms"):
        assert make_spec(time_format=mode).time_format == mode
    for bad in ("apache", "ISO8601", "", None, 5, True, ["iso8601"]):
        with pytest.raises(CustomFormatError):
            make_spec(time_format=bad)


def test_policy_fingerprint_keeps_legacy_identity():
    legacy_absent = load_spec({"format_id": "custom-t5b1", "pattern": PATTERN})
    legacy_explicit = make_spec(time_format="combined")
    assert enrichment_policy("custom", legacy_absent) == enrichment_policy(
        "custom", legacy_explicit
    )
    assert enrichment_policy("custom", legacy_absent).startswith("t1b.1+custom:")
    iso = enrichment_policy("custom", make_spec(time_format="iso8601"))
    epoch_s = enrichment_policy("custom", make_spec(time_format="epoch_s"))
    epoch_ms = enrichment_policy("custom", make_spec(time_format="epoch_ms"))
    assert len({enrichment_policy("custom", legacy_absent), iso, epoch_s, epoch_ms}) == 4


# --- ISO-8601 mode ---


def test_iso8601_z_and_offsets_normalize_to_same_utc():
    zulu = parse_custom("2026-10-27T09:15:32Z", time_format="iso8601")
    plus_one = parse_custom("2026-10-27T10:15:32+01:00", time_format="iso8601")
    minus = parse_custom("2026-10-27T04:15:32-05:00", time_format="iso8601")
    compact = parse_custom("2026-10-27T10:15:32+0100", time_format="iso8601")
    for record in (zulu, plus_one, minus, compact):
        assert record.timestamp_utc == datetime(2026, 10, 27, 9, 15, 32, tzinfo=UTC)
    assert (zulu.tz_offset_minutes, plus_one.tz_offset_minutes) == (0, 60)
    assert (minus.tz_offset_minutes, compact.tz_offset_minutes) == (-300, 60)


def test_iso8601_fractions_keep_microseconds_and_truncate_beyond():
    millis = parse_custom("2026-10-27T09:15:32.5Z", time_format="iso8601")
    assert millis.timestamp_utc.microsecond == 500000
    micros = parse_custom("2026-10-27T09:15:32.123456Z", time_format="iso8601")
    assert micros.timestamp_utc.microsecond == 123456
    nanos = parse_custom("2026-10-27T09:15:32.123456789Z", time_format="iso8601")
    assert nanos.timestamp_utc.microsecond == 123456


@pytest.mark.parametrize(
    "bad",
    [
        "2026-10-27T09:15:32",  # naive: no offset, never guessed
        "2026-10-27 09:15:32+00:00",  # space separator rejected
        "2026-10-27T09:15:32z",  # lowercase zone rejected
        "2026-10-27T09:15:32+00",  # short offset rejected
        "2026-10-27T09:15:32+24:00",  # offset out of range
        "2026-10-27T24:00:00Z",  # hour out of range
        "2026-10-27T09:15:60Z",  # leap second rejected
        "2026-13-27T09:15:32Z",
        "2026-10-27T09:15:32.Z",
        "2026-10-27T09:15:32.1234567890Z",  # >9 fraction digits
        "27/Oct/2026:09:15:32 +0000",  # combined text under iso mode
        "1761550532",  # epoch text under iso mode
    ],
)
def test_iso8601_rejects_malformed(bad):
    item = parse_custom(bad, time_format="iso8601")
    assert item.reason == "invalid_time"
    assert item.excerpt == "<withheld>:invalid_time"


def test_iso8601_empty_time_is_malformed_line():
    # An empty time group fails the custom pattern shape itself, before
    # any timestamp validation runs: still one fixed withheld rejection.
    item = parse_custom("", time_format="iso8601")
    assert item.reason == "malformed_line"
    assert item.excerpt == "<withheld>:malformed_line"


# --- Epoch modes ---


def test_epoch_modes_match_independent_datetime():
    moment = datetime(2026, 10, 27, 9, 15, 32, tzinfo=UTC)
    stamp = int(moment.timestamp())
    by_s = parse_custom(str(stamp), time_format="epoch_s")
    assert by_s.timestamp_utc == moment
    assert by_s.tz_offset_minutes == 0
    by_ms = parse_custom(str(stamp * 1000 + 250), time_format="epoch_ms")
    assert by_ms.timestamp_utc == moment + timedelta(milliseconds=250)
    frac_s = parse_custom(f"{stamp}.000001", time_format="epoch_s")
    assert frac_s.timestamp_utc == moment + timedelta(microseconds=1)
    trunc = parse_custom(f"{stamp}.0000019", time_format="epoch_s")
    assert trunc.timestamp_utc == moment + timedelta(microseconds=1)
    epoch_zero = parse_custom("0", time_format="epoch_s")
    assert epoch_zero.timestamp_utc == datetime(1970, 1, 1, tzinfo=UTC)


def test_epoch_ms_fraction_truncates_to_microseconds():
    moment = datetime(2026, 10, 27, 9, 15, 32, tzinfo=UTC)
    stamp_ms = int(moment.timestamp() * 1000)
    assert parse_custom(
        f"{stamp_ms}.5", time_format="epoch_ms"
    ).timestamp_utc == moment + timedelta(microseconds=500)


@pytest.mark.parametrize("mode", ["epoch_s", "epoch_ms"])
@pytest.mark.parametrize(
    "bad",
    [
        "-5",
        "+5",
        "1e10",
        "0x10",
        "inf",
        "nan",
        "12.5.6",
        " 1761550532",
        "1761550532 ",
        "١٢٣",
        "99999999999999999999",
        "1" + "0" * 40 + ".5",
    ],
)
def test_epoch_rejects_malformed_and_out_of_range(mode, bad):
    item = parse_custom(bad, time_format=mode)
    assert item.reason == "invalid_time"
    assert item.excerpt == "<withheld>:invalid_time"


@pytest.mark.parametrize("mode", ["epoch_s", "epoch_ms"])
def test_epoch_absurd_tokens_hit_field_budget_first(mode):
    # Tokens past the generic captured-field budget abort with the
    # fixed budget code before timestamp validation: still one safe
    # rejection, no conversion, no echo, no crash.
    item = parse_custom("9" * 5000, time_format=mode)
    assert item.reason == "oversized_field"
    assert item.excerpt == "<withheld>:oversized_field"


def test_epoch_max_instant_and_overflow():
    moment = datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)
    # Integer arithmetic only: float total_seconds() cannot spell this instant.
    epoch_us = (moment - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1)
    assert epoch_us == 253402300799999999
    stamp_s, stamp_ms = epoch_us // 1_000_000, epoch_us // 1_000
    assert parse_custom(str(stamp_s), time_format="epoch_s").timestamp_utc == moment.replace(
        microsecond=0
    )
    assert parse_custom(str(stamp_ms), time_format="epoch_ms").timestamp_utc == moment.replace(
        microsecond=999000
    )
    assert parse_custom(str(stamp_s + 1), time_format="epoch_s").reason == "invalid_time"
    assert parse_custom(str(stamp_ms + 1), time_format="epoch_ms").reason == "invalid_time"


def test_unknown_mode_raises_fixed_code():
    with pytest.raises(ValueError, match="invalid_time"):
        _normalize_time_with_mode("x", "bogus")
    assert _normalize_time_with_mode("27/Oct/2026:09:15:32 +0000", COMBINED_TIME)[0] == datetime(
        2026, 10, 27, 9, 15, 32, tzinfo=UTC
    )


# --- Byte domain ---


def test_bytes_domain_bounds():
    assert MAX_BYTES_VALUE == 2**63 - 1
    assert normalize_bytes_value("-") is None
    assert normalize_bytes_value("0") == 0
    assert normalize_bytes_value("153") == 153
    assert normalize_bytes_value("007") == 7
    assert normalize_bytes_value(str(2**63 - 1)) == 2**63 - 1
    for bad in (
        str(2**63),
        "9" * 5000,
        "0" * 5000,
        "-5",
        "+5",
        "12.5",
        "0x10",
        "1e3",
        "inf",
        "nan",
        "",
        " 12",
        "12 ",
        "١٢٣",
    ):
        with pytest.raises(ValueError, match="invalid_bytes"):
            normalize_bytes_value(bad)


def test_bytes_bounds_all_presets_and_custom():
    line = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 '
        + str(2**63 - 1).encode()
        + b' "-" "T5b1/1.0"'
    )
    common_line = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 '
        + str(2**63 - 1).encode()
    )
    vhost_line = b"example.org " + line
    cases = [
        (NGINX_COMBINED, line),
        (APACHE_COMBINED, line),
        (COMMON, common_line),
        (APACHE_VHOST_COMBINED, vhost_line),
    ]
    for format_id, raw in cases:
        record = parse_line(raw, source_id="s", format_id=format_id, hmac_key=HMAC_KEY)
        assert getattr(record, "bytes_sent", None) == 2**63 - 1, format_id
    extended_raw = (
        b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 '
        + str(2**63 - 1).encode()
        + b' "-" "T5b1/1.0" example.org - - - - "-"'
    )
    record = parse_line(extended_raw, source_id="s", format_id=NGINX_EXTENDED, hmac_key=HMAC_KEY)
    assert record.bytes_sent == 2**63 - 1
    assert record.extra.request_time_ms is None
    custom_ok = parse_custom("2026-10-27T09:15:32Z", size=str(2**63 - 1), time_format="iso8601")
    assert custom_ok.bytes_sent == 2**63 - 1
    assert parse_custom("2026-10-27T09:15:32Z", size="-", time_format="iso8601").bytes_sent is None
    assert parse_custom("2026-10-27T09:15:32Z", size="0", time_format="iso8601").bytes_sent == 0


def test_bytes_overflow_rejects_once_without_binding(tmp_path):
    good = custom_line("2026-10-27T09:15:32Z", size="128")
    # A 20-digit token fits the field budget and fails the int64 domain.
    bad = b'203.0.113.21 [2026-10-27T09:15:33Z] "GET /big HTTP/1.1" 200 99999999999999999999'
    assert (
        parse_custom("2026-10-27T09:15:33Z", size="9" * 20, time_format="iso8601").reason
        == "invalid_bytes"
    )
    # A 5000-digit token trips the generic field budget first: still a
    # fixed withheld rejection with no conversion attempt.
    assert (
        parse_custom("2026-10-27T09:15:33Z", size="9" * 5000, time_format="iso8601").reason
        == "oversized_field"
    )
    target = tmp_path / "sizes.log"
    target.write_bytes(good + b"\n" + bad + b"\n" + good + b"\n")
    spec = make_spec(time_format="iso8601")
    records, report = collect_records(
        target, source_id="s", format_id="custom-t5b1", hmac_key=HMAC_KEY, custom_format=spec
    )
    assert [record.line_number for record in records] == [1, 3]
    assert all(record.bytes_sent == 128 for record in records)
    assert report.accepted == 2 and report.rejected == 1
    assert report.rejected_by_reason == {"invalid_bytes": 1}
    assert report.diagnostics[0].excerpt == "<withheld>:invalid_bytes"
    assert "9999999999" not in report.diagnostics[0].excerpt


@pytest.mark.parametrize("format_id", [NGINX_COMBINED, APACHE_COMBINED, COMMON])
def test_preset_bytes_overflow_token_rejects(format_id):
    size = b"9" * 5000
    if format_id == COMMON:
        raw = b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 ' + size
    else:
        raw = (
            b'203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /x HTTP/1.1" 200 '
            + size
            + b' "-" "-"'
        )
    item = parse_line(raw, source_id="s", format_id=format_id, hmac_key=HMAC_KEY)
    assert item.reason == "invalid_bytes"
    assert item.excerpt == "<withheld>:invalid_bytes"

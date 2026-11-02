"""T5b1b corrections (unit): carry ordering, ISO bounds, empty byte field.

Synthetic fixtures only. Expected values were derived by hand and
pasted in; ordering expectations follow exact integer totals.
"""

import sqlite3
from datetime import UTC, datetime

import pytest

from app.analytics.contracts import AnalyticsFilter, TimeWindow, TopPathsQuery
from app.analytics.queries import _TOP_PATH_ORDER, top_paths
from app.ingestion.combined import (
    _normalize_iso8601_time,
    _normalize_time,
    normalize_bytes_value,
)
from app.ingestion.custom import load_spec, parse_custom_line

HMAC_KEY = b"t5b1b-unit-hmac-key"


def _filt(**overrides):
    base = {
        "site_id": "default",
        "window": TimeWindow(
            time_from=datetime(2026, 10, 27, tzinfo=UTC),
            time_to=datetime(2026, 10, 28, tzinfo=UTC),
        ),
    }
    base.update(overrides)
    return AnalyticsFilter(**base)


def _mem_db(rows):
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE requests (site_id TEXT, source_id TEXT, ts_utc TEXT,"
        " method TEXT, path TEXT, status INT, bytes INT, referer_host TEXT,"
        " user_agent TEXT, client_pseudonym TEXT, server_host TEXT,"
        " http_version TEXT, mime_type TEXT, cache_status TEXT, tls_protocol TEXT,"
        " request_time_ms REAL, upstream_time_ms REAL, country_code TEXT)"
    )
    conn.executemany(
        "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
    )
    return conn


def _row(path, size, ts="2026-10-27T09:00:00+00:00", method="GET", client="c"):
    return (
        "default",
        None,
        ts,
        method,
        path,
        200,
        size,
        None,
        None,
        client,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )


# --- 1. exact carry ordering ---


def test_bytes_desc_normalizes_low_word_carry():
    conn = _mem_db(
        [
            _row("/carry-a", 4294967296, client="a"),
            _row("/carry-b", 2147483649, client="b"),
            _row("/carry-b", 2147483649, client="b"),
        ]
    )
    items, _ = top_paths(conn, TopPathsQuery(filt=_filt(), sort="bytes_desc"))
    assert [item["path"] for item in items] == ["/carry-b", "/carry-a"]
    assert items[0]["bytes_total"] == 4294967298
    assert items[1]["bytes_total"] == 4294967296
    assert all(isinstance(item["bytes_total"], int) for item in items)
    conn.close()


def test_bytes_desc_tie_breaks_requests_path_method():
    # Equal exact totals: more requests first, then path, then method.
    conn = _mem_db(
        [
            _row("/tie", 100, method="POST", client="a"),
            _row("/tie", 100, method="GET", client="b"),
            _row("/aaa", 200, client="c"),
        ]
    )
    items, _ = top_paths(conn, TopPathsQuery(filt=_filt(), sort="bytes_desc"))
    # /tie GET+POST groups each total 100; /aaa totals 200 and ranks first.
    assert items[0] == {
        "path": "/aaa",
        "method": "GET",
        "requests": 1,
        "errors": 0,
        "bytes_total": 200,
    }
    # Tied 100-byte groups order by path then method deterministically.
    assert [item["method"] for item in items[1:]] == ["GET", "POST"]
    assert all(item["bytes_total"] == 100 for item in items[1:])
    conn.close()


def test_bytes_desc_offset_pages_full_ranking():
    conn = _mem_db(
        [
            _row("/carry-a", 4294967296, client="a"),
            _row("/carry-b", 2147483649, client="b"),
            _row("/carry-b", 2147483649, client="b"),
        ]
    )
    page, total = top_paths(
        conn,
        TopPathsQuery(filt=_filt(limit=1, offset=1), sort="bytes_desc"),
    )
    assert total == 2
    assert len(page) == 1
    assert page[0]["path"] == "/carry-a"
    assert page[0]["bytes_total"] == 4294967296
    conn.close()


def test_only_top_paths_orders_by_split_halves():
    order = _TOP_PATH_ORDER["bytes_desc"]
    assert "bytes_hi" in order and "bytes_lo" in order
    # Carry normalization, exact totals, stable tie-breaks preserved.
    assert "(bytes_hi + (bytes_lo >> 32)) DESC" in order
    assert "(bytes_lo & 4294967295) DESC" in order
    assert order.endswith("requests DESC, path ASC, method ASC")
    assert "REAL" not in order.upper()


# --- 2. ISO offset validation and UTC bounds ---


@pytest.mark.parametrize("bad", ["+00:60", "-01:99", "+23:60", "+24:00", "-24:00"])
def test_iso_rejects_bad_offset_components(bad):
    with pytest.raises(ValueError, match="invalid_time"):
        _normalize_iso8601_time(f"2026-10-27T09:15:32{bad}")


@pytest.mark.parametrize(
    ("text", "minutes"),
    [
        ("2026-10-27T09:15:32Z", 0),
        ("2026-10-27T10:15:32+01:00", 60),
        ("2026-10-27T04:15:32-05:00", -300),
        ("2026-10-27T10:15:32+0100", 60),
        ("2026-10-27T09:15:32.5Z", 0),
    ],
)
def test_iso_valid_spellings_unchanged(text, minutes):
    from datetime import timedelta

    moment, offset = _normalize_iso8601_time(text)
    expected = datetime(2026, 10, 27, 9, 15, 32, tzinfo=UTC)
    if ".5" in text:
        expected += timedelta(microseconds=500000)
    assert moment == expected
    assert offset == minutes


def test_iso_fraction_precision_unchanged():
    moment, _ = _normalize_iso8601_time("2026-10-27T09:15:32.123456789Z")
    assert moment.microsecond == 123456


@pytest.mark.parametrize(
    "bad",
    ["0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"],
)
def test_iso_utc_overflow_rejects_without_escaping(bad):
    with pytest.raises(ValueError, match="invalid_time"):
        _normalize_iso8601_time(bad)


def test_legacy_utc_overflow_rejects_without_changing_valid():
    with pytest.raises(ValueError, match="invalid_time"):
        _normalize_time("01/Jan/0001:00:00:00 +2359")
    moment, offset = _normalize_time("27/Oct/2026:09:15:32 +0000")
    assert moment == datetime(2026, 10, 27, 9, 15, 32, tzinfo=UTC)
    assert offset == 0


# --- 3. empty custom byte field ---


def _pipe_spec(group="size"):
    return load_spec(
        {
            "format_id": "custom-t5b1b",
            "pattern": (
                r"^(?P<host>[^|]+)\|(?P<time>[^|]+)\|(?P<request>[^|]+)"
                rf"\|(?P<status>[0-9]{{3}})\|(?P<{group}>[^|]*)$"
            ),
            "time_format": "iso8601",
        }
    )


@pytest.mark.parametrize("group", ["size", "bytes"])
def test_empty_captured_bytes_rejects(group):
    spec = _pipe_spec(group)
    item = parse_custom_line(
        b"203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|",
        spec=spec,
        source_id="s",
        hmac_key=HMAC_KEY,
        line_number=1,
    )
    assert item.reason == "invalid_bytes"
    assert item.excerpt == "<withheld>:invalid_bytes"


@pytest.mark.parametrize("group", ["size", "bytes"])
def test_dash_zero_max_bytes_aliases(group):
    spec = _pipe_spec(group)
    base = "203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200|"
    assert (
        parse_custom_line(
            (base + "-").encode(), spec=spec, source_id="s", hmac_key=HMAC_KEY
        ).bytes_sent
        is None
    )
    assert (
        parse_custom_line(
            (base + "0").encode(), spec=spec, source_id="s", hmac_key=HMAC_KEY
        ).bytes_sent
        == 0
    )
    assert (
        parse_custom_line(
            (base + str(2**63 - 1)).encode(),
            spec=spec,
            source_id="s",
            hmac_key=HMAC_KEY,
        ).bytes_sent
        == 2**63 - 1
    )


def test_absent_size_mapping_keeps_none_contract():
    spec = load_spec(
        {
            "format_id": "custom-t5b1c",
            "pattern": (
                r"^(?P<host>[^|]+)\|(?P<time>[^|]+)\|(?P<request>[^|]+)\|(?P<status>[0-9]{3})$"
            ),
            "time_format": "iso8601",
        }
    )
    record = parse_custom_line(
        b"203.0.113.30|2026-10-27T09:15:32Z|GET /safe HTTP/1.1|200",
        spec=spec,
        source_id="s",
        hmac_key=HMAC_KEY,
    )
    assert record.bytes_sent is None


def test_normalize_bytes_value_still_rejects_empty():
    with pytest.raises(ValueError, match="invalid_bytes"):
        normalize_bytes_value("")

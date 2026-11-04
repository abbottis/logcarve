"""T5a unit tests: offline country lookup (PAR-09).

Pure unit coverage over :mod:`app.ingestion.geoip` with synthetic
data and in-memory fake readers only: no database file, no network,
no real addresses. Globally routable example addresses below are
TEST-ONLY lookup inputs, never real runtime observations.
"""

import pytest

from app.ingestion.geoip import (
    DBIP_COUNTRY_LITE_TYPE,
    GEO_SOURCE_DBIP,
    GEO_STATUS_HIT,
    GEO_STATUS_UNAVAILABLE,
    GEO_STATUS_UNKNOWN,
    CountryLookup,
    is_lookup_eligible,
    normalize_country_code,
    normalize_country_selector,
)


class FakeReader:
    """Minimal in-memory MMDB stand-in: records calls, never I/O."""

    def __init__(self, records=None, database_type=DBIP_COUNTRY_LITE_TYPE):
        self.records = dict(records or {})
        self.database_type = database_type
        self.build_epoch = 1761955200  # 2026-11-01T00:00:00Z -> "2026-11"
        self.calls: list[str] = []
        self.closed = False

    def metadata(self):
        inner = self

        class _Meta:
            database_type = inner.database_type
            build_epoch = inner.build_epoch

        return _Meta()

    def get(self, ip_text):
        self.calls.append(ip_text)
        if ip_text == "raise.example":
            raise RuntimeError("synthetic reader failure")
        return self.records.get(ip_text)

    def close(self):
        self.closed = True


def _lookup(records=None, **overrides):
    reader = FakeReader(records)
    kwargs = {
        "source": GEO_SOURCE_DBIP,
        "release": "2026-11",
        "database_type": DBIP_COUNTRY_LITE_TYPE,
        "available": True,
    }
    kwargs.update(overrides)
    return CountryLookup(reader, **kwargs), reader


# --- record shape -----------------------------------------------------


def test_normalize_country_code_accepts_dbip_and_nested_shapes():
    assert normalize_country_code({"country_code": "DE"}) == "DE"
    assert normalize_country_code({"country_code": "us"}) == "US"
    assert normalize_country_code({"country": {"iso_code": "FR"}}) == "FR"
    assert normalize_country_code({"country": {"iso_code": "zz"}}) is None


def test_normalize_country_code_rejects_everything_else():
    assert normalize_country_code(None) is None
    assert normalize_country_code({}) is None
    assert normalize_country_code({"country_code": "ZZ"}) is None
    assert normalize_country_code({"country_code": "D"}) is None
    assert normalize_country_code({"country_code": "DEU"}) is None
    assert normalize_country_code({"country_code": "D1"}) is None
    assert normalize_country_code({"country_code": 42}) is None
    assert normalize_country_code({"country": {"iso_code": None}}) is None
    assert normalize_country_code({"other": "DE"}) is None
    assert normalize_country_code("DE") is None


def test_normalize_country_selector_shared_allowlist():
    assert normalize_country_selector(None) is None
    assert normalize_country_selector("de") == "DE"
    assert normalize_country_selector(" US ") == "US"
    assert normalize_country_selector("unknown") == "UNKNOWN"
    assert normalize_country_selector("Unknown") == "UNKNOWN"
    for bad in ("", "   ", "D", "DEU", "D1", "U*", "UNKNOWNX"):
        with pytest.raises(ValueError):
            normalize_country_selector(bad)


# --- eligibility ------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "   ",
        "not-an-ip",
        "999.1.1.1",
        "10.0.0.1",  # private v4
        "172.16.0.1",  # private v4
        "192.168.1.1",  # private v4
        "127.0.0.1",  # loopback v4
        "::1",  # loopback v6
        "169.254.1.1",  # link-local v4
        "fe80::1",  # link-local v6
        "224.0.0.1",  # multicast v4
        "ff02::1",  # multicast v6
        "0.0.0.0",  # unspecified v4
        "::",  # unspecified v6
        "192.0.2.1",  # documentation TEST-NET-1
        "198.51.100.7",  # documentation TEST-NET-2
        "203.0.113.9",  # documentation TEST-NET-3
        "2001:db8::1",  # documentation v6
        "4000::1",  # reserved AND is_global on current Python
        "::ffff:192.0.2.1",  # IPv4-mapped documentation
        "100.64.0.1",  # shared CGNAT, not globally routable
        "192.0.0.170",  # NAT64 reserved range sample
    ],
)
def test_reserved_private_and_special_addresses_stay_unknown(text):
    assert is_lookup_eligible(text) is False


@pytest.mark.parametrize("text", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "::ffff:8.8.8.8"])
def test_global_addresses_are_eligible(text):
    assert is_lookup_eligible(text) is True


def test_eligibility_blocks_database_value_for_special_address():
    lookup, reader = _lookup({"10.0.0.1": {"country_code": "US"}})
    info = lookup.lookup("10.0.0.1")
    assert info.code is None
    assert info.status == GEO_STATUS_UNKNOWN
    assert reader.calls == []


# --- lookup behavior --------------------------------------------------


def test_hit_unknown_and_unavailable_outcomes():
    lookup, _reader = _lookup(
        {"8.8.8.8": {"country_code": "US"}, "9.9.9.9": {"country": {"iso_code": "DE"}}}
    )
    hit = lookup.lookup("8.8.8.8")
    assert (hit.code, hit.status, hit.source, hit.release) == (
        "US",
        GEO_STATUS_HIT,
        GEO_SOURCE_DBIP,
        "2026-11",
    )
    nested = lookup.lookup("9.9.9.9")
    assert (nested.code, nested.status) == ("DE", GEO_STATUS_HIT)
    missing = lookup.lookup("1.1.1.1")
    assert missing.code is None and missing.status == GEO_STATUS_UNKNOWN
    assert missing.source == GEO_SOURCE_DBIP
    assert missing.release == "2026-11"


def test_reader_exception_is_unknown_not_fatal():
    lookup, _reader = _lookup({})
    info = lookup.lookup("8.8.8.8")
    assert info.code is None and info.status == GEO_STATUS_UNKNOWN


def test_zz_record_stays_unknown():
    lookup, _reader = _lookup({"8.8.8.8": {"country_code": "ZZ"}})
    assert lookup.lookup("8.8.8.8").status == GEO_STATUS_UNKNOWN


def test_unavailable_handle_answers_unavailable():
    lookup = CountryLookup.unavailable()
    assert lookup.available is False
    info = lookup.lookup("8.8.8.8")
    assert info.code is None and info.status == GEO_STATUS_UNAVAILABLE
    assert lookup.describe() == {
        "available": False,
        "source": None,
        "release": None,
        "database_type": None,
        "status": "unavailable",
    }


def test_describe_reports_honest_provenance():
    lookup, _reader = _lookup({})
    assert lookup.describe() == {
        "available": True,
        "source": GEO_SOURCE_DBIP,
        "release": "2026-11",
        "database_type": DBIP_COUNTRY_LITE_TYPE,
        "status": "ready",
    }


def test_close_is_idempotent_and_stops_lookups():
    lookup, reader = _lookup({"8.8.8.8": {"country_code": "US"}})
    lookup.close()
    lookup.close()
    assert reader.closed is True
    assert lookup.available is False
    info = lookup.lookup("8.8.8.8")
    assert info.status == GEO_STATUS_UNAVAILABLE


def test_cache_bounds_repeated_clients():
    lookup, _reader = _lookup({"8.8.8.8": {"country_code": "US"}})
    first = lookup.lookup("8.8.8.8")
    second = lookup.lookup("8.8.8.8")
    assert first == second
    assert len(lookup._cache) == 1


def test_context_manager_closes():
    reader = FakeReader()
    with CountryLookup(reader, available=True) as lookup:
        assert lookup.available is True
    assert reader.closed is True
    assert lookup.available is False


# --- open() gating ----------------------------------------------------


def test_open_missing_and_garbage_paths_are_unavailable(tmp_path):
    assert CountryLookup.open(None).available is False
    assert CountryLookup.open(tmp_path / "absent.mmdb").available is False
    assert CountryLookup.open(tmp_path).available is False  # a directory
    garbage = tmp_path / "garbage.mmdb"
    garbage.write_bytes(b"not a maxmind database")
    assert CountryLookup.open(garbage).available is False


def test_open_wrong_database_type_is_unavailable_and_closes(monkeypatch, tmp_path):
    probe = tmp_path / "wrong.mmdb"
    probe.write_bytes(b"synthetic probe content")
    made: list[FakeReader] = []

    class WrongTypeReader(FakeReader):
        def __init__(self):
            super().__init__({}, database_type="GeoLite2-Country")
            made.append(self)

    import maxminddb

    monkeypatch.setattr(maxminddb, "open_database", lambda path, mode=None: WrongTypeReader())
    lookup = CountryLookup.open(probe)
    assert lookup.available is False
    assert lookup.describe()["status"] == "unavailable"
    assert made and made[0].closed is True
    assert lookup.lookup("8.8.8.8").status == GEO_STATUS_UNAVAILABLE


def test_open_accepts_genuine_dbip_type(monkeypatch, tmp_path):
    probe = tmp_path / "dbip.mmdb"
    probe.write_bytes(b"synthetic probe content")
    made: list[FakeReader] = []

    class GenuineReader(FakeReader):
        def __init__(self):
            super().__init__({"8.8.8.8": {"country_code": "US"}})
            made.append(self)

    import maxminddb

    monkeypatch.setattr(maxminddb, "open_database", lambda path, mode=None: GenuineReader())
    with CountryLookup.open(probe) as lookup:
        assert lookup.available is True
        assert lookup.describe()["database_type"] == DBIP_COUNTRY_LITE_TYPE
        assert lookup.lookup("8.8.8.8").code == "US"
    assert made and made[0].closed is True


def test_no_mmdb_file_inside_public_source_tree():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    found = [
        path
        for path in root.rglob("*.mmdb")
        if ".git" not in path.parts and "node_modules" not in path.parts
    ]
    assert found == []

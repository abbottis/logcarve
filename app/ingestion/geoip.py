"""Genuine offline country lookup over a local MMDB file (T5a, PAR-09).

The reader opens one operator-mounted database file (DB-IP Country
Lite format, ``dbip-country-lite-YYYY-MM.mmdb``) read-only and answers
``reader.get(ip)`` locally: no network request, no paid service, no
hash-to-country map. The database file itself is never bundled in Git
and never enters the Contributor context; only a configured mount
path is read at import time.

Privacy shape: the validated client-address text is looked up
transiently during the ingestion/enrichment hook, before the raw
address is discarded or encrypted. Only a safe ISO 3166-1 alpha-2
code (or ``NULL`` for Unknown) plus the lookup source/release/status
needed for honest coverage is persisted. Original addresses never
reach exports, errors, API schemas, model tools or public Git.

Honesty rules, enforced here and covered by tests:

* private, reserved, loopback, link-local, multicast, documentation,
  unspecified and invalid addresses are always ``Unknown`` — even if
  a database happens to return a value for them (checked before any
  reader call);
* a country is never inferred from an HMAC pseudonym (the lookup
  takes address text only);
* a record value is accepted only as two ASCII uppercase letters
  (``ZZ`` — the unspecified-country marker — stays ``Unknown``);
* a missing, corrupt or unreadable database yields fixed
  ``unavailable`` markers and ordinary analytics keep working; an
  explicitly required database fails the import before any write
  with a fixed code (never paths, addresses or exception text).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

#: Lookup outcome persisted per row (``geo_status``).
GEO_STATUS_HIT = "hit"
GEO_STATUS_UNKNOWN = "unknown"
GEO_STATUS_UNAVAILABLE = "unavailable"

#: Source label persisted for DB-IP Country Lite rows (``geo_source``).
GEO_SOURCE_DBIP = "dbip-country-lite"

#: The only MMDB ``database_type`` this reader accepts. The genuine
#: DB-IP Country Lite file reports exactly this type (coordinator
#: verified against the downloaded file metadata); any other type —
#: a MaxMind GeoLite2-Country file, an ASN database, a City database
#: or anything else mis-mounted — yields an unavailable handle with
#: fixed markers instead of a mislabelled ``dbip-country-lite``
#: provenance row. Never widen this allowlist silently: adding a new
#: database family needs an explicit code change plus its own
#: provenance label and license handling.
DBIP_COUNTRY_LITE_TYPE = "DBIP-Country-Lite"

#: Validated ``country=`` selector for Unknown rows (NULL country code).
UNKNOWN_COUNTRY = "UNKNOWN"

#: Accepted stored/selected codes: exactly two ASCII uppercase letters.
COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")

#: Unspecified-country marker some databases return: stays Unknown.
UNSPECIFIED_COUNTRY = "ZZ"

#: Documentation/example networks (TEST-NET-1/2/3, TEST-NET-6) that
#: must stay Unknown even on Python builds where ``is_reserved`` does
#: not cover them. Checked with a version-guarded containment test so
#: an IPv4 address never compares against an IPv6 network.
_DOCUMENTATION_NETWORKS: tuple[Any, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

#: Attribution required by the CC BY 4.0 database license on every page
#: showing country results.
GEO_ATTRIBUTION_URL = "https://db-ip.com"
GEO_ATTRIBUTION_TEXT = "IP Geolocation by DB-IP"
#: Human-readable database name and license traveling with country
#: data (UI credit, API/export metadata, client summaries): safe
#: display strings only, never a filesystem path or key.
GEO_DATABASE_NAME = "DB-IP Country Lite"
GEO_DATABASE_LICENSE = "CC BY 4.0"

#: Fixed failure when a required database is missing or unusable. The
#: import fails before any write; the code carries no path or reason
#: detail that could leak deployment layout.
GEOIP_REQUIRED_CODE = "geoip_unavailable:database_required"

#: Bounded per-handle lookup cache: one small entry per distinct
#: address keeps repeated clients cheap without unbounded growth.
LOOKUP_CACHE_MAX = 4096


class GeoipError(RuntimeError):
    """A required GeoIP database is missing or unusable (fixed code only)."""

    def __init__(self, code: str = GEOIP_REQUIRED_CODE) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CountryInfo:
    """One transient lookup outcome. Only safe fields persist."""

    code: str | None
    status: str
    source: str | None
    release: str | None


def normalize_country_code(record: Any) -> str | None:
    """Extract a safe ISO code from one MMDB record, else ``None``.

    DB-IP Country Lite records carry ``country_code``; the nested
    ``country.iso_code`` shape is accepted as a documented fallback
    for genuine DB-IP record-shape variants. (A mis-mounted
    non-DB-IP database never reaches this function: :meth:`open`
    rejects a wrong ``database_type`` up front.) Anything else —
    missing keys, wrong types, wrong lengths, the ``ZZ``
    unspecified marker — is ``Unknown``, never a default country.
    """
    candidate: Any = None
    if isinstance(record, dict):
        candidate = record.get("country_code")
        if candidate is None:
            country = record.get("country")
            if isinstance(country, dict):
                candidate = country.get("iso_code")
    if not isinstance(candidate, str):
        return None
    code = candidate.strip().upper()
    if code == UNSPECIFIED_COUNTRY:
        return None
    if not COUNTRY_CODE_RE.match(code):
        return None
    return code


def normalize_country_selector(value: str | None) -> str | None:
    """Validate one ``country`` filter value to its stored canonical form.

    The single shared allowlist for every transport (dashboard, REST,
    model tools, saved views): ``None`` stays ``None`` (no filter);
    the explicit ``UNKNOWN`` selector (any case) selects rows with no
    known country; anything else must be exactly two ASCII letters
    (stored and compared uppercase). Anything else raises
    ``ValueError`` so callers reject instead of silently widening —
    and an empty value never selects Unknown.
    """
    if value is None:
        return None
    text = value.strip().upper()
    if text == UNKNOWN_COUNTRY:
        return UNKNOWN_COUNTRY
    if COUNTRY_CODE_RE.match(text):
        return text
    raise ValueError(f"unknown country selector: {value!r}")


def is_lookup_eligible(text: str | None) -> bool:
    """True only for globally routable addresses worth a database read.

    Everything else — invalid text, private, reserved, loopback,
    link-local, multicast, documentation and unspecified addresses —
    stays ``Unknown`` without consulting the database, so a stray
    database value for such an address can never surface.
    """
    if not isinstance(text, str) or not text:
        return False
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    # Explicit exclusion list: ``is_global`` alone is not enough
    # (for example ``4000::1`` reports ``is_reserved`` AND
    # ``is_global`` on current Python). Any flagged address stays
    # Unknown without consulting the database, even if the database
    # would return a country for it.
    if addr.is_multicast:
        return False
    if addr.is_private:
        return False
    if addr.is_reserved:
        return False
    if addr.is_loopback:
        return False
    if addr.is_link_local:
        return False
    if addr.is_unspecified:
        return False
    if bool(getattr(addr, "is_documentation", False)):
        return False
    candidates = [addr]
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        candidates.append(mapped)
    for candidate in candidates:
        for network in _DOCUMENTATION_NETWORKS:
            try:
                if candidate.version != network.version:
                    continue
                if candidate in network:
                    return False
            except TypeError:
                return False
    return bool(addr.is_global)


def _release_from_epoch(build_epoch: Any) -> str | None:
    """Honest ``YYYY-MM`` release from database metadata, else ``None``."""
    if isinstance(build_epoch, bool):
        return None
    if not isinstance(build_epoch, (int, float)):
        return None
    try:
        moment = datetime.fromtimestamp(float(build_epoch), UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime("%Y-%m")


class CountryLookup:
    """Read-only country lookup over one mounted MMDB file.

    Open with :meth:`open` (or use :meth:`unavailable` when no path is
    configured): the handle owns one MMDB reader for the whole import
    or reprocess run and must be closed afterwards. Lookups never
    leave the host; a closed or unavailable handle answers
    ``unavailable`` instead of raising.
    """

    def __init__(
        self,
        reader: Any = None,
        *,
        source: str | None = None,
        release: str | None = None,
        database_type: str | None = None,
        available: bool = False,
    ) -> None:
        self._reader = reader
        self._source = source
        self._release = release
        self._database_type = database_type
        self._available = bool(available and reader is not None)
        self._closed = False
        self._cache: dict[str, CountryInfo] = {}

    @classmethod
    def unavailable(cls) -> CountryLookup:
        """Unconfigured handle: every lookup reports ``unavailable``."""
        return cls()

    @classmethod
    def open(cls, db_path: str | Path | None, *, source: str = GEO_SOURCE_DBIP) -> CountryLookup:
        """Open the mounted database read-only; never raise for bad input.

        A missing, unreadable or invalid file yields an unavailable
        handle with fixed markers (no path, address or exception text
        escapes), so ordinary analytics keep working. Callers with a
        required-database policy check :attr:`available` and fail
        before any write.
        """
        if db_path is None:
            return cls.unavailable()
        path = Path(db_path)
        try:
            is_file = path.is_file()
        except OSError:
            return cls.unavailable()
        if not is_file:
            return cls.unavailable()
        try:
            import maxminddb

            reader = maxminddb.open_database(path, mode=maxminddb.MODE_MMAP)
        except Exception:  # noqa: BLE001 - fixed unavailability, never the text
            return cls.unavailable()
        try:
            metadata = reader.metadata()
            database_type = getattr(metadata, "database_type", None)
            release = _release_from_epoch(getattr(metadata, "build_epoch", None))
        except Exception:  # noqa: BLE001 - fixed unavailability, never the text
            try:
                reader.close()
            except Exception:  # noqa: BLE001, S110 - close is best-effort
                pass
            return cls.unavailable()
        if database_type != DBIP_COUNTRY_LITE_TYPE:
            # Wrong database family mounted (MaxMind country/ASN/city
            # or anything else): close the handle so no descriptor
            # leaks, then report unavailable with fixed markers. This
            # keeps a mis-mounted file from ever surfacing rows
            # mislabelled as DB-IP Country Lite.
            try:
                reader.close()
            except Exception:  # noqa: BLE001, S110 - close is best-effort
                pass
            return cls.unavailable()
        return cls(
            reader,
            source=source,
            release=release,
            database_type=str(database_type) if database_type is not None else None,
            available=True,
        )

    @property
    def available(self) -> bool:
        """True when lookups can hit the mounted database."""
        return self._available and not self._closed

    def lookup(self, ip_text: str | None) -> CountryInfo:
        """Country for one validated address text; never raises."""
        key = ip_text.strip() if isinstance(ip_text, str) else ""
        if not key:
            return CountryInfo(None, GEO_STATUS_UNKNOWN, None, None)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        info = self._lookup_uncached(key)
        if len(self._cache) >= LOOKUP_CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = info
        return info

    def _lookup_uncached(self, key: str) -> CountryInfo:
        if not is_lookup_eligible(key):
            return CountryInfo(None, GEO_STATUS_UNKNOWN, None, None)
        if not self.available or self._reader is None:
            return CountryInfo(None, GEO_STATUS_UNAVAILABLE, None, None)
        try:
            record = self._reader.get(key)
        except Exception:  # noqa: BLE001 - one bad read is Unknown, not fatal
            return CountryInfo(None, GEO_STATUS_UNKNOWN, self._source, self._release)
        if record is None:
            return CountryInfo(None, GEO_STATUS_UNKNOWN, self._source, self._release)
        code = normalize_country_code(record)
        if code is None:
            return CountryInfo(None, GEO_STATUS_UNKNOWN, self._source, self._release)
        return CountryInfo(code, GEO_STATUS_HIT, self._source, self._release)

    def describe(self) -> dict[str, object]:
        """Honest lookup provenance for coverage display (safe fields only)."""
        return {
            "available": self.available,
            "source": self._source if self.available else None,
            "release": self._release if self.available else None,
            "database_type": self._database_type if self.available else None,
            "status": "ready" if self.available else "unavailable",
        }

    def close(self) -> None:
        """Release the read-only handle (idempotent, best-effort)."""
        self._closed = True
        reader, self._reader = self._reader, None
        self._available = False
        if reader is not None:
            try:
                reader.close()
            except Exception:  # noqa: BLE001, S110 - close is best-effort
                pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

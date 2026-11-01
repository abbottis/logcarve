"""Display-timezone catalogue for the browser dashboard.

The dashboard renders stored UTC instants in one explicit display
timezone. The catalogue is the server-installed IANA set from stdlib
``zoneinfo.available_timezones`` (already filtered by the stdlib: the
``posix/``, ``right/`` and ``localtime`` special entries are excluded),
cached once per process so request handling never re-enumerates the
zoneinfo files. Every supported key is retained, including aliases; the
server validates any requested name against this catalogue plus a
``ZoneInfo`` construction check, so unknown or filesystem-style values
fail safely without ever touching a filesystem path from input.

Ordering is stable and readable: the configured server default first,
then ``UTC`` (unless identical), then remaining regions alphabetically
with zone/city names alphabetical within each region. Labels replace
underscores with spaces for readability; option values stay exact IANA
keys. Selection stays a native ``<select>`` for keyboard access.

Default precedence: an explicit valid ``tz`` URL value always wins. When
absent, the validated ``DEFAULT_TIMEZONE`` configuration applies. Only
an exact installed IANA region key from the operator ``TZ`` environment
counts as a reliable local server name; a container cannot infer
geographic location from a datetime abbreviation or fixed offset, so
those are never guessed. Anything unusable names ``UTC``
deterministically. Naming UTC is always safe; *rendering* any zone
(including UTC) still requires the system tz database — without usable
zone data the data pages fail fast with a safe 400 instead of showing
unconverted times.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

FALLBACK_TIMEZONE = "UTC"


@lru_cache(maxsize=1)
def _catalog() -> tuple[str, ...]:
    """Installed IANA keys, cached; safe fallback when the DB is absent."""
    try:
        keys = available_timezones()
    except OSError:
        return (FALLBACK_TIMEZONE,)
    if not keys:
        return (FALLBACK_TIMEZONE,)
    return tuple(keys)


def catalog_keys() -> frozenset[str]:
    """All supported timezone names (exact IANA values)."""
    return frozenset(_catalog())


def _sort_key(name: str) -> tuple[str, str]:
    """Region first, then the remaining zone path, both alphabetical."""
    region, _, rest = name.partition("/")
    return (region, rest)


@lru_cache(maxsize=1)
def _sorted_rest() -> tuple[str, ...]:
    """Catalogue minus UTC, in stable region/zone order (cached)."""
    return tuple(sorted((k for k in _catalog() if k != FALLBACK_TIMEZONE), key=_sort_key))


def is_supported(name: object) -> bool:
    """True only for an exact installed key that also constructs."""
    if not isinstance(name, str) or not name or name not in catalog_keys():
        return False
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


@lru_cache(maxsize=1024)
def _zone(name: str) -> ZoneInfo:
    """Bounded cache of constructed zones; one object reused per request.

    Capacity 1024 covers the whole installed catalogue (currently ~599
    keys), so two full catalogue renderings share every zone object
    instead of re-opening hundreds of zone files per request. Caller
    input never reaches the cache key unchecked: only exact installed
    catalogue keys are constructed.
    """
    return ZoneInfo(name)


def offset_at(name: str, ref: datetime | None) -> object | None:
    """Signed UTC offset of ``name`` at instant ``ref`` (window start).

    Returns a ``timedelta`` (east positive, west negative, fractional
    and sub-minute values preserved) or ``None`` when the zone or the
    reference cannot be resolved. Never touches the filesystem with
    caller input: only exact catalogue keys are constructed.
    """
    try:
        zone = _zone(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None
    moment = ref
    if moment is None:
        moment = datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    try:
        return moment.astimezone(zone).utcoffset()
    except (ValueError, OverflowError, OSError):
        return None


def format_offset_suffix(name: str, ref: datetime | None) -> str:
    """Signed `UTC±HH:MM` suffix for ``name`` at ``ref`` (window start).

    Exact hours and minutes; seconds are appended only for historical
    sub-minute offsets. Falls back to an unavailable marker instead of
    guessing when the offset cannot be resolved.
    """
    from datetime import timedelta

    delta = offset_at(name, ref)
    if not isinstance(delta, timedelta):
        return "UTC offset unavailable"
    total = int(delta.total_seconds())
    sign = "+" if total >= 0 else "-"
    rest = abs(total)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)
    if seconds:
        return f"UTC{sign}{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def display_label(name: str, ref: datetime | None = None) -> str:
    """Readable option label with signed offset; value stays the exact key.

    The offset is calculated for the applied window start ``ref``
    (never the review date), so historical and DST windows read
    truthfully. ``ref=None`` falls back to now for non-window callers.
    """
    readable = name.replace("_", " ")
    return f"{readable} — {format_offset_suffix(name, ref)}"


def ordered_timezones(default: str | None = None) -> list[str]:
    """Stable option order: validated default, UTC, then region/zone order.

    An invalid or missing default contributes nothing (UTC covers it);
    duplicates never appear.
    """
    options = [FALLBACK_TIMEZONE]
    if (
        isinstance(default, str)
        and default
        and default != FALLBACK_TIMEZONE
        and is_supported(default)
    ):
        options.insert(0, default)
    ordered = options + [k for k in _sorted_rest() if k not in options]
    return ordered


def display_options(
    default: str | None = None, ref: datetime | None = None
) -> list[dict[str, str]]:
    """Option dicts for the native timezone ``<select>``.

    Labels carry the signed offset at the applied window start ``ref``;
    option values stay exact IANA keys.
    """
    return [
        {"value": name, "label": display_label(name, ref)} for name in ordered_timezones(default)
    ]


def _is_env_region_key(name: str) -> bool:
    """True only for a defensible auto-detected server region key.

    Explicit ``tz``/configured values may use any exact installed alias
    (including ``CET``); automatic ``TZ`` detection must name a real
    region (``Region/City``) or ``UTC``. Abbreviations (``CET``/``EST``),
    fixed-offset ``Etc/*`` entries and filesystem/path syntax never
    identify a region and are never guessed from.
    """
    if name == FALLBACK_TIMEZONE:
        return True
    if "/" not in name or "\\" in name:
        return False
    if name.startswith("Etc/"):
        return False
    return not name.startswith(("/", "."))


def resolve_default_timezone(configured: str | None = None) -> str:
    """Effective default when the URL carries no explicit ``tz``.

    Validated configuration wins. Otherwise an exact installed IANA
    *region* key from the operator ``TZ`` environment is a reliable
    local server name and applies; abbreviations, fixed offsets and
    path syntax fall back to ``UTC`` deterministically even when they
    happen to be installed aliases. Never reads timezone files directly
    and never accepts a filesystem path.
    """
    if isinstance(configured, str) and configured and is_supported(configured):
        return configured
    env_tz = os.environ.get("TZ", "")
    if env_tz and _is_env_region_key(env_tz) and is_supported(env_tz):
        return env_tz
    return FALLBACK_TIMEZONE


def resolve_request_timezone(raw: str | None, configured: str | None = None) -> str | None:
    """Explicit valid ``tz`` wins; blank falls back to the default.

    Returns the validated IANA name, or ``None`` for an invalid explicit
    value so the caller can reject it safely.
    """
    if raw is not None and raw.strip():
        candidate = raw.strip()
        # Reject filesystem-style input before any catalogue lookup.
        if "\\" in candidate or any(ord(c) < 0x20 or ord(c) == 0x7F for c in candidate):
            return None
        if not is_supported(candidate):
            return None
        return candidate
    return resolve_default_timezone(configured)

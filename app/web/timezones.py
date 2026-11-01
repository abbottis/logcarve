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
an exact installed IANA key from the operator ``TZ`` environment counts
as a reliable local server name; a container cannot infer geographic
location from a datetime abbreviation or fixed offset, so those are never
guessed. Anything unusable falls back to ``UTC`` deterministically.
"""

from __future__ import annotations

import os
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


def display_label(name: str) -> str:
    """Readable option label; the submitted value stays the exact key."""
    return name.replace("_", " ")


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


def display_options(default: str | None = None) -> list[dict[str, str]]:
    """Option dicts for the native timezone ``<select>``."""
    return [{"value": name, "label": display_label(name)} for name in ordered_timezones(default)]


def resolve_default_timezone(configured: str | None = None) -> str:
    """Effective default when the URL carries no explicit ``tz``.

    Validated configuration wins. Otherwise an exact installed IANA key
    from the operator ``TZ`` environment is a reliable local server name
    and applies. Abbreviations and fixed offsets never identify a region,
    so anything else falls back to ``UTC`` deterministically. Never reads
    timezone files directly and never accepts a filesystem path.
    """
    if isinstance(configured, str) and configured and is_supported(configured):
        return configured
    env_tz = os.environ.get("TZ", "")
    if env_tz and is_supported(env_tz):
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

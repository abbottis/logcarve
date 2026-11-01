"""Conservative conflicting-bot-identity detection (Stage B).

A User-Agent that carries unambiguous named identity tokens for TWO OR
MORE DISTINCT providers is a POTENTIAL spoof/inconsistency candidate —
never a verified fake bot and never a justification to auto-block or to
remove rows from counts. Original client addresses are discarded at
import, so real reverse/forward-DNS or range verification cannot run
here; no DNS, HTTP, GeoIP, unmasking or bot removal is performed.

The known set is deliberately small and explicit: each entry pairs one
token with exactly one provider, matched at actual token boundaries
after URL substrings are stripped, so documentation links such as
``+http://www.google.com/bot.html`` never count as an identity claim.
Excluded by construction: ``Mozilla`` compatibility markers, generic
``bot``/``crawl``/``curl``/monitoring substrings, ``notgooglebot``-style
affixed tokens, and two variants of the SAME provider (only one provider
matches, so no conflict).

The same pure, cached helpers back the SQLite scalar
``conflicting_bot(user_agent)`` (all-row SQL aggregation over the full
selected scope, no Python row loading) and the per-row web signal, so
the query layer, the service layer and the dashboard always agree.
"""

from __future__ import annotations

import re
from functools import lru_cache

#: Explicit known set: (token, provider). Every token is unambiguous
#: (exactly one provider); providers are pairwise distinct so any two
#: token hits mean two distinct providers. Coverage is documented here
#: and in Help rather than broadened by guessing.
KNOWN_CONFLICT_IDENTITIES: tuple[tuple[str, str], ...] = (
    ("Googlebot", "Google"),
    ("bingbot", "Microsoft"),
    ("GPTBot", "OpenAI"),
    ("ClaudeBot", "Anthropic"),
    ("AhrefsBot", "Ahrefs"),
    ("SemrushBot", "Semrush"),
    ("MJ12bot", "Majestic"),
    ("YandexBot", "Yandex"),
    ("Baiduspider", "Baidu"),
)

#: Rule reference for the deterministic security finding.
CONFLICT_RULE_ID = "sec-conflicting-bot-identity"
CONFLICT_RULE_VERSION = 1
CONFLICT_CATEGORY = "conflicting_bot_identity"

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# Token boundaries are ASCII alphanumerics: "notgooglebot" (affixed) and
# version suffixes ("Googlebot/2.1") behave correctly — the former never
# matches, the latter always does. Matching is case-insensitive, like the
# versioned classifier.
_TOKEN_RES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (
        re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])", re.IGNORECASE),
        provider,
    )
    for token, provider in KNOWN_CONFLICT_IDENTITIES
)

_MAX_CONFLICT_CACHE = 4096


def _strip_urls(user_agent: str) -> str:
    """Remove URL substrings so documentation links never claim identity."""
    return _URL_RE.sub("", user_agent)


@lru_cache(maxsize=_MAX_CONFLICT_CACHE)
def conflict_providers(user_agent: str) -> frozenset[str]:
    """Distinct known providers whose tokens appear in ``user_agent``.

    Empty for missing agents, Mozilla-only strings, generic bot/monitor
    markers, docs-URL-only mentions and single-provider claims (including
    two variants of the same provider).
    """
    if not isinstance(user_agent, str) or not user_agent:
        return frozenset()
    cleaned = _strip_urls(user_agent)
    if not cleaned:
        return frozenset()
    return frozenset(
        provider for pattern, provider in _TOKEN_RES if pattern.search(cleaned) is not None
    )


def is_conflicting(user_agent: str | None) -> bool:
    """True only when two or more distinct known providers are claimed."""
    if not isinstance(user_agent, str) or not user_agent:
        return False
    return len(conflict_providers(user_agent)) >= 2


def sqlite_conflicting_bot(user_agent: object) -> int:
    """SQLite scalar: 1 for a conflicting UA, else 0 (never NULL)."""
    if not isinstance(user_agent, str) or not user_agent:
        return 0
    return 1 if is_conflicting(user_agent) else 0

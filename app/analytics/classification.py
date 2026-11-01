"""Ordered User-Agent classification shared by SQL and Python (Slice A).

File order is match order: the first rule whose pattern matches wins, so
specific patterns (``googlebot-image``) must precede generic ones
(``googlebot``). A single combined alternation with ``search()`` can NOT
express this: the regex engine prefers the earliest text position over
the earliest alternative, so a trailing browser group would match
``Mozilla`` at position 0 and hide a later ``GPTBot``. Instead every row
evaluates one ordered predicate list with early exit, in SQL through the
registered ``classify_ua(user_agent, spec)`` scalar and in Python through
:func:`classify_one` over the identical order. A bounded per-UA cache
keeps repeated agents O(1); there is deliberately NOT one SQL function
call per rule per row.

``spec`` is a server-generated string built only from the versioned admin
rule file (escaped literals plus file-validated ``ua_regex`` entries) and
travels as a bound parameter, never as interpolated SQL. Client input can
never supply patterns. Unknown rule keys or NULL agents classify as
unknown; legacy ``bot_family`` columns stay untouched (no write-on-read).
"""

import hashlib
import re
from dataclasses import dataclass
from functools import lru_cache

from app.analytics.rules import Rule

#: Fallback marker for browser-like agents. Checked only after every bot
#: rule, so bot UAs that mention browsers (e.g. Chrome-Lighthouse) still
#: classify by rule. An unmatched UA without a marker is unknown, never
#: proven human traffic.
BROWSER_MARKER = (
    r"mozilla/|applewebkit|gecko|chrome|crios|safari|"
    r"firefox|fxios|edg/|edgios|opr/|opera|mobile|tablet|"
    r"windows nt|macintosh|x11|linux"
)

#: Rule categories that map to each traffic bucket. Security categories
#: have no UA matchers; a UA rule carrying one is rejected at build time.
TRAFFIC_BY_CATEGORY = {
    "search_crawler": "claimed_bot",
    "ai_crawler": "claimed_bot",
    "seo_tool": "claimed_bot",
    "social_bot": "claimed_bot",
    "federation_crawler": "claimed_bot",
    "feed_fetcher": "claimed_bot",
    "generic_bot": "claimed_bot",
    "monitoring": "other_automation",
    "automation_tool": "other_automation",
    "suspected_automation": "other_automation",
    "unknown": "unknown",
}

_SPEC_SEPARATOR = "\x1f"
_MAX_SPEC_CACHE = 16
_MAX_UA_CACHE = 4096


@dataclass(frozen=True)
class Classifier:
    """Ordered match state for one versioned rule list."""

    key: str
    spec: str
    rule_ids: tuple[str, ...]
    rules: tuple[Rule, ...]
    traffic: tuple[str, ...]
    categories: tuple[str, ...]
    providers: tuple[object, ...]
    purposes: tuple[object, ...]
    versions: tuple[int, ...]
    browser_index: int


def _pattern_for(rule: Rule) -> str:
    parts = [re.escape(fragment) for fragment in rule.ua_contains]
    parts.extend(rule.ua_regex)
    return "(?:" + "|".join(parts) + ")"


def build_classifier(rules: list[Rule]) -> Classifier:
    """Compile ordered predicates from UA rules in file order.

    Only rules with UA matchers take part; path/count rules are skipped.
    Unknown categories or security categories with UA matchers raise
    instead of silently mapping.
    """
    ua_rules = [r for r in rules if r.ua_contains or r.ua_regex]
    patterns = []
    traffic: list[str] = []
    for rule in ua_rules:
        bucket = TRAFFIC_BY_CATEGORY.get(rule.category)
        if bucket is None:
            raise ValueError(f"rule {rule.id} has no traffic mapping")
        patterns.append(_pattern_for(rule))
        traffic.append(bucket)
    spec = _SPEC_SEPARATOR.join([*patterns, f"(?:{BROWSER_MARKER})"])
    key = hashlib.sha1(spec.encode("utf-8")).hexdigest()
    browser_index = len(ua_rules)
    return Classifier(
        key=key,
        spec=spec,
        rule_ids=tuple(r.id for r in ua_rules),
        rules=tuple(ua_rules),
        traffic=tuple(traffic),
        categories=tuple(r.category for r in ua_rules),
        providers=tuple(r.provider for r in ua_rules),
        purposes=tuple(r.purpose for r in ua_rules),
        versions=tuple(r.version for r in ua_rules),
        browser_index=browser_index,
    )


@lru_cache(maxsize=_MAX_SPEC_CACHE)
def _compiled_spec(spec: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(part, re.IGNORECASE) for part in spec.split(_SPEC_SEPARATOR))


@lru_cache(maxsize=_MAX_UA_CACHE)
def _match_cached(spec: str, user_agent: str) -> int | None:
    """First matching predicate index, browser_index fallback, else None."""
    for index, rx in enumerate(_compiled_spec(spec)):
        if rx.search(user_agent) is not None:
            return index
    return None


def sqlite_classify_ua(user_agent: object, spec: object) -> int | None:
    """SQLite scalar: ordered rule index, browser_index, or NULL unknown."""
    if not isinstance(user_agent, str) or not user_agent:
        return None
    if not isinstance(spec, str) or not spec:
        return None
    return _match_cached(spec, user_agent)


def register_sqlite_functions(conn) -> None:
    """Register the classifier scalar on one DB-API connection."""
    conn.create_function("classify_ua", 2, sqlite_classify_ua, deterministic=True)


def classify_one(user_agent: str | None, classifier: Classifier) -> tuple[int | None, str]:
    """Python mirror of the SQL scalar: (index|None, traffic bucket).

    ``None`` index means unknown (no rule, no browser marker, or no UA).
    The browser fallback index maps to ``browser_like``.
    """
    if not user_agent:
        return None, "unknown"
    index = _match_cached(classifier.spec, user_agent)
    if index is None:
        return None, "unknown"
    if index == classifier.browser_index:
        return index, "browser_like"
    return index, classifier.traffic[index]


def resolve_selector_indexes(
    classifier: Classifier,
    *,
    bot: str | None = None,
    category: str | None = None,
    provider: str | None = None,
    purpose: str | None = None,
) -> set[int] | None:
    """Narrow rule indexes for validated selectors; None means no narrowing.

    Unknown bots/providers/purposes and bot-selector contradictions raise
    ``ValueError`` so callers reject instead of widening or ignoring.
    """
    if bot is None and category is None and provider is None and purpose is None:
        return None
    if bot is not None and bot not in classifier.rule_ids:
        raise ValueError(f"unknown bot selector: {bot!r}")
    known_providers = {p for p in classifier.providers if p is not None}
    if provider is not None and provider not in known_providers:
        raise ValueError(f"unknown provider selector: {provider!r}")
    known_purposes = {p for p in classifier.purposes if p is not None}
    if purpose is not None and purpose not in known_purposes:
        raise ValueError(f"unknown purpose selector: {purpose!r}")
    allowed = set(range(len(classifier.rule_ids)))
    if bot is not None:
        allowed &= {classifier.rule_ids.index(bot)}
    if category is not None:
        allowed &= {i for i, c in enumerate(classifier.categories) if c == category}
    if provider is not None:
        allowed &= {i for i, p in enumerate(classifier.providers) if p == provider}
    if purpose is not None:
        allowed &= {i for i, p in enumerate(classifier.purposes) if p == purpose}
    if (
        bot is not None or category is not None or provider is not None or purpose is not None
    ) and not allowed:
        raise ValueError("contradictory bot selectors match no rule")
    return allowed


def traffic_indexes(classifier: Classifier, traffic: str) -> set[int] | None:
    """Rule indexes in one traffic bucket (browser/unknown handled by callers)."""
    return {i for i, t in enumerate(classifier.traffic) if t == traffic}

"""Stage B unit tests: conservative conflicting-bot-identity detection.

Pure User-Agent assertions over the hand-authored 9-token known set:
positives need unambiguous named tokens for two or more DISTINCT
providers at actual token boundaries; everything else (single claims,
same-provider variants, Mozilla compatibility, generic/monitoring
markers, docs-URL substrings, affixed tokens, missing or hostile
agents) stays negative. The SQLite scalar agrees with the Python
helpers, and first-match classification of conflicting agents is
unchanged.
"""

import sqlite3
from pathlib import Path

from app.analytics.classification import build_classifier, classify_one, register_sqlite_functions
from app.analytics.conflict import (
    CONFLICT_CATEGORY,
    CONFLICT_RULE_ID,
    CONFLICT_RULE_VERSION,
    KNOWN_CONFLICT_IDENTITIES,
    conflict_providers,
    is_conflicting,
    sqlite_conflicting_bot,
)
from app.analytics.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = load_rules(ROOT / "config" / "bot_rules.yaml").rules


def test_known_set_is_explicit_and_pairwise_distinct():
    assert len(KNOWN_CONFLICT_IDENTITIES) >= 9
    tokens = [token for token, _ in KNOWN_CONFLICT_IDENTITIES]
    assert len(set(tokens)) == len(tokens)
    providers = [provider for _, provider in KNOWN_CONFLICT_IDENTITIES]
    assert len(set(providers)) == len(providers)
    assert dict(KNOWN_CONFLICT_IDENTITIES)["Googlebot"] == "Google"


def test_rule_reference_constants_match_shipped_rule():
    sec = {rule.id: rule for rule in load_rules(ROOT / "config" / "security_rules.yaml").rules}
    rule = sec[CONFLICT_RULE_ID]
    assert rule.version == CONFLICT_RULE_VERSION
    assert rule.category == CONFLICT_CATEGORY


def test_positive_two_provider_claims():
    assert is_conflicting("Mozilla/5.0 (compatible; Googlebot/2.1; bingbot/2.0)")
    assert conflict_providers("Mozilla/5.0 (compatible; Googlebot/2.1; bingbot/2.0)") == {
        "Google",
        "Microsoft",
    }
    assert is_conflicting("GPTBot/1.1 (+https://openai.com/gptbot); ClaudeBot/1.0")
    assert is_conflicting("AhrefsBot/7.0; SemrushBot/7~bl (+http://example.org/)")
    assert is_conflicting("MJ12bot/v1.4.8 (+http://mj12bot.example/) YandexBot/3.0")
    assert is_conflicting("Baiduspider/2.0 (+http://www.baidu.com/search/spider.htm) GPTBot/1.0")


def test_semicolon_joined_pair_conflicts():
    ua = "Mozilla/5.0; Googlebot/2.1; bingbot/2.0"
    assert is_conflicting(ua)


def test_normal_single_claims_stay_negative():
    assert not is_conflicting(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    assert not is_conflicting(
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    )
    assert not is_conflicting("Mozilla/5.0")
    assert not is_conflicting(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36"
    )
    assert not is_conflicting("curl/8.0")
    assert not is_conflicting("UptimeRobot/2.0")
    assert not is_conflicting("generic-bot-crawler/1.0")
    assert not is_conflicting("notgooglebot/1.0")
    assert not is_conflicting("MyGooglebotClone/1.0 (+https://example.org/)")


def test_same_provider_variants_stay_negative():
    # Googlebot plus another Google-only claim is one provider, not a conflict.
    assert not is_conflicting("Googlebot/2.1 Googlebot-Image/1.2")
    assert conflict_providers("Googlebot/2.1 Googlebot-Image/1.2") == {"Google"}


def test_docs_url_substrings_and_non_tokens_stay_negative():
    # A documentation URL mentioning a token is not an identity claim.
    assert not is_conflicting("SomeCrawler/1.0 (+https://example.com/googlebot-info)")
    assert not is_conflicting("FeedFetcher-Google/1.0")
    # Training/indexing prose without a named token never conflicts.
    assert not is_conflicting("AI training crawler")
    assert not is_conflicting("bot")


def test_missing_and_hostile_agents_stay_negative():
    assert not is_conflicting(None)
    assert not is_conflicting("")
    assert not is_conflicting("   ")
    long_ua = "A" * 8000 + " Googlebot/2.1 " + "B" * 8000
    assert not is_conflicting(long_ua)
    long_conflict = "Googlebot/2.1 " + "x" * 8000 + " bingbot/2.0"
    assert is_conflicting(long_conflict)
    assert not is_conflicting("Googlebot\x00/2.1 <script>alert(1)</script>")


def test_sqlite_scalar_agrees_with_python():
    conn = sqlite3.connect(":memory:")
    try:
        register_sqlite_functions(conn)
        for ua, want in [
            ("Mozilla/5.0 (compatible; Googlebot/2.1; bingbot/2.0)", 1),
            ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 0),
            ("Mozilla/5.0", 0),
            (None, 0),
            ("", 0),
        ]:
            row = conn.execute("SELECT conflicting_bot(?)", (ua,)).fetchone()
            assert row[0] == want, ua
            assert row[0] == (1 if is_conflicting(ua) else 0)
    finally:
        conn.close()
    assert sqlite_conflicting_bot(None) == 0
    assert sqlite_conflicting_bot("") == 0


def test_first_match_classification_unchanged_for_conflicts():
    clf = build_classifier(list(BOT_RULES))
    index, traffic = classify_one("Mozilla/5.0 (compatible; Googlebot/2.1; bingbot/2.0)", clf)
    # First match in catalog order (Googlebot precedes bingbot) still wins.
    assert clf.rule_ids[index] == "bot-search-google"
    assert traffic == "claimed_bot"

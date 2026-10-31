"""T4 rule tests: versioned bot/security files load, validate and match claims."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analytics.rules import Rule, RuleSet, load_rules

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = ROOT / "config" / "bot_rules.yaml"
SEC_RULES = ROOT / "config" / "security_rules.yaml"


def test_shipped_rule_files_load_with_versions():
    bots = load_rules(BOT_RULES)
    sec = load_rules(SEC_RULES)
    assert bots.version == 2
    assert sec.version == 1
    assert bots.provenance and sec.provenance
    assert {rule.id for rule in bots.rules} >= {
        "bot-search-google",
        "bot-search-bing",
        "bot-ai-gpt",
        "bot-ai-claude",
        "bot-ai-perplexity",
    }
    assert {rule.id for rule in sec.rules} == {"sec-sensitive-path", "sec-repeated-client-errors"}


def test_ua_matching_is_case_insensitive_claim_only():
    rule = next(r for r in load_rules(BOT_RULES).rules if r.id == "bot-search-google")
    assert rule.matches_ua("googlebot/2.1 (+http://www.google.com/bot.html)")
    assert rule.matches_ua("Mozilla/5.0 (compatible; GoogleBot/2.1)")
    assert not rule.matches_ua("Mozilla/5.0")
    assert not rule.matches_ua(None)
    assert "not verified" in rule.meaning


def test_path_matching_is_case_insensitive():
    rule = next(r for r in load_rules(SEC_RULES).rules if r.id == "sec-sensitive-path")
    assert rule.matches_path("/.ENV")
    assert rule.matches_path("/app/.git/config")
    assert not rule.matches_path("/about")


def test_behavioral_rule_carries_explicit_threshold():
    rule = next(r for r in load_rules(SEC_RULES).rules if r.id == "sec-repeated-client-errors")
    assert rule.min_client_errors == 5
    assert not rule.ua_contains and not rule.path_contains


def test_duplicate_ids_and_matcherless_rules_rejected(tmp_path):
    with pytest.raises(ValidationError):
        RuleSet(
            version=1,
            provenance="test",
            rules=[
                Rule(
                    id="a", version=1, category="unknown", title="t", meaning="m", ua_contains=["x"]
                ),
                Rule(
                    id="a", version=1, category="unknown", title="t", meaning="m", ua_contains=["y"]
                ),
            ],
        )
    with pytest.raises(ValidationError):
        Rule(id="b", version=1, category="unknown", title="t", meaning="m")
    with pytest.raises(ValidationError):
        RuleSet.model_validate(
            {
                "version": 1,
                "provenance": "t",
                "rules": [
                    {
                        "id": "BAD ID",
                        "version": 1,
                        "category": "unknown",
                        "title": "t",
                        "meaning": "m",
                        "ua_contains": ["x"],
                    }
                ],
            }
        )


def test_non_mapping_rule_file_rejected(tmp_path):
    bogus = tmp_path / "rules.yaml"
    bogus.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(TypeError, match="mapping"):
        load_rules(bogus)

"""Slice A: ordered UA classifier, catalog breadth and selector validation."""

import json
from pathlib import Path

import pytest

from app.analytics.classification import (
    build_classifier,
    classify_one,
    resolve_selector_indexes,
)
from app.analytics.rules import Rule, load_rules

ROOT = Path(__file__).resolve().parent.parent.parent
BOT_RULES = ROOT / "config" / "bot_rules.yaml"

VECTORS = json.loads(
    (ROOT / "tests" / "fixtures" / "expected" / "ua_vectors.json").read_text(encoding="utf-8")
)["vectors"]


@pytest.fixture(scope="module")
def catalog():
    return load_rules(BOT_RULES)


@pytest.fixture(scope="module")
def classifier(catalog):
    return build_classifier(catalog.rules)


def test_catalog_holds_adapted_plus_original_rules(catalog):
    assert catalog.version == 3
    assert len(catalog.rules) == 77
    ids = [rule.id for rule in catalog.rules]
    assert len(set(ids)) == 77
    for kept in (
        "bot-search-google",
        "bot-search-bing",
        "bot-ai-gpt",
        "bot-ai-claude",
        "bot-ai-perplexity",
    ):
        assert kept in ids
    assert "bot-mon-uptimerobot" in ids
    assert "bot-suspected-generic" in ids
    by_id = {rule.id: rule for rule in catalog.rules}
    assert by_id["bot-mon-uptimerobot"].category == "monitoring"
    assert by_id["bot-mon-uptimerobot"].provider == "UptimeRobot"
    assert by_id["bot-suspected-generic"].category == "suspected_automation"
    # Specifics precede generics in file order so first match wins.
    assert ids.index("bot-search-google-image") < ids.index("bot-search-google")
    assert ids.index("bot-search-yandexbot") < ids.index("bot-search-yandex")
    assert ids.index("bot-auto-masscan") < ids.index("bot-suspected-generic")
    assert ids.index("bot-search-google") < ids.index("bot-suspected-generic")


def test_every_rule_carries_claim_wording(catalog):
    limiting = (
        "not verified",
        "never a crawler",
        "never a proven crawler",
        "never a verified check",
        "never a verified crawler",
        "investigation lead",
        "suspected automation",
    )
    for rule in catalog.rules:
        assert any(phrase in rule.meaning for phrase in limiting), rule.id
        assert rule.ua_contains or rule.ua_regex


def test_mirror_matches_hand_vectors(classifier):
    assert len(VECTORS) == 51
    for vector in VECTORS:
        index, traffic = classify_one(vector["ua"], classifier)
        rule = (
            classifier.rule_ids[index]
            if index is not None and index != classifier.browser_index
            else None
        )
        assert rule == vector["rule"], vector
        assert traffic == vector["traffic"], vector


def test_file_priority_beats_text_position(classifier):
    index, traffic = classify_one("Mozilla/5.0 GPTBot/1.0", classifier)
    assert classifier.rule_ids[index] == "bot-ai-gpt"
    assert traffic == "claimed_bot"
    index, _ = classify_one("Bingbot-test Googlebot/2.1", classifier)
    assert classifier.rule_ids[index] == "bot-search-google"


def test_n8n_word_boundaries(classifier):
    index, _ = classify_one("n8n automate", classifier)
    assert classifier.rule_ids[index] == "bot-auto-n8n"
    assert classify_one("an8n9/x", classifier) == (None, "unknown")
    assert classify_one("somen8nthing", classifier) == (None, "unknown")


def test_empty_and_missing_agents_are_unknown(classifier):
    assert classify_one("", classifier) == (None, "unknown")
    assert classify_one(None, classifier) == (None, "unknown")


def test_resolve_rejects_unknown_and_contradictory_selectors(classifier):
    assert resolve_selector_indexes(classifier) is None
    only = resolve_selector_indexes(classifier, bot="bot-ai-gpt")
    assert only == {classifier.rule_ids.index("bot-ai-gpt")}
    with pytest.raises(ValueError):
        resolve_selector_indexes(classifier, bot="bot-nope")
    with pytest.raises(ValueError):
        resolve_selector_indexes(classifier, provider="No Such Provider")
    with pytest.raises(ValueError):
        resolve_selector_indexes(classifier, purpose="No Such Purpose")
    with pytest.raises(ValueError):
        resolve_selector_indexes(classifier, bot="bot-ai-gpt", category="search_crawler")


def test_ua_rule_with_security_category_is_rejected():
    rules = [
        Rule(
            id="bad",
            version=1,
            category="sensitive_path",
            title="t",
            meaning="m",
            ua_contains=["x"],
        )
    ]
    with pytest.raises(ValueError):
        build_classifier(rules)

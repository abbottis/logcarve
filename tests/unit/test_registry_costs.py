"""Registry cost normalization unit tests: exact per-model integers.

Pure offline tests with hand-computed expectations: no network, no
keys, no provider account. No mirror of implementation internals:
every expectation is an independent hand calculation from the
verified per-million rates in each adapter.
"""

import pytest

from app.ai import registry


def test_meta_cost_unchanged():
    # Meta Standard: 1.25/0.15/4.25 per M (verified 2026-10-31).
    assert (
        registry.cost_for(
            "meta",
            {"input_tokens": 1_000_000, "output_tokens": 0, "cached_tokens": 0},
        )
        == 1_250_000
    )
    assert (
        registry.cost_for(
            "meta",
            {"input_tokens": 1_000_000, "output_tokens": 100_000, "cached_tokens": 200_000},
        )
        == 1_455_000
    )


def test_openai_cost_luna_rates():
    # Luna Standard: .10/.01/.50 per M.
    assert (
        registry.cost_for(
            "openai",
            {"input_tokens": 2_000_000, "output_tokens": 0, "cached_tokens": 0},
        )
        == 200_000
    )
    assert (
        registry.cost_for(
            "openai",
            {"input_tokens": 1_000_000, "output_tokens": 100_000, "cached_tokens": 200_000},
        )
        == 132_000
    )


def test_gemini_cost_flash_lite_rates():
    # Flash-Lite paid: .30/.03/2.50 per M, output includes thoughts.
    assert (
        registry.cost_for(
            "gemini",
            {"input_tokens": 1_000_000, "output_tokens": 0, "cached_tokens": 0},
        )
        == 300_000
    )
    assert (
        registry.cost_for(
            "gemini",
            {"input_tokens": 1_000_000, "output_tokens": 100_000, "cached_tokens": 200_000},
        )
        == 496_000
    )


def test_anthropic_cost_tiers_and_disjoint_caches():
    # Small tier (<=100k total input): .10/.50/.01 per M, 5m writes
    # .125, 1h/unknown writes .20. The adapter reports input_tokens as
    # the disjoint total (base+created+read). 90k base + 10k unknown
    # creation + 1k output = 9000 + 2000 + 500 micro-USD.
    assert (
        registry.cost_for(
            "anthropic",
            {
                "input_tokens": 100_000,
                "output_tokens": 1_000,
                "cached_tokens": 0,
                "cache_creation_tokens": 10_000,
                "reasoning_tokens": 0,
            },
        )
        == 11_500
    )
    # Explicit 5-minute creation bills at its own lower rate: 90k base
    # + 10k 5m creation + 1k output = 9000 + 1250 + 500 micro-USD.
    assert (
        registry.cost_for(
            "anthropic",
            {
                "input_tokens": 100_000,
                "output_tokens": 1_000,
                "cached_tokens": 0,
                "cache_creation_tokens": 0,
                "cache_creation_5m_tokens": 10_000,
                "reasoning_tokens": 0,
            },
        )
        == 10_750
    )
    # Reads bill at the cached rate inside the small tier.
    assert (
        registry.cost_for(
            "anthropic",
            {
                "input_tokens": 100_000,
                "output_tokens": 0,
                "cached_tokens": 10_000,
                "cache_creation_tokens": 0,
                "reasoning_tokens": 0,
            },
        )
        == 9_100
    )
    # Large tier (>100k total input): .50/2.50/.05 per M, conservative.
    assert (
        registry.cost_for(
            "anthropic",
            {
                "input_tokens": 100_001,
                "output_tokens": 0,
                "cached_tokens": 0,
                "cache_creation_tokens": 0,
                "reasoning_tokens": 0,
            },
        )
        == 50_001
    )


def test_step_caps_are_conservative_upper_bounds():
    for provider in ("meta", "openai", "gemini", "anthropic"):
        cap = registry.step_cap_for(provider, input_upper=10_000, max_output_tokens=2048)
        assert cap > 0
        measured = registry.cost_for(
            provider,
            {
                "input_tokens": 10_000,
                "output_tokens": 2048,
                "cached_tokens": 0,
                "cache_creation_tokens": 0,
                "reasoning_tokens": 0,
            },
        )
        assert cap >= measured


def test_unknown_provider_cost_fails_closed():
    with pytest.raises((KeyError, ValueError)):
        registry.cost_for("nope", {"input_tokens": 1, "output_tokens": 1})

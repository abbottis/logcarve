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


def test_openai_cost_terra_rates():
    # Terra Standard: 1.00/0.05/2.50-write/5.00 per M, subsets disjoint.
    assert (
        registry.cost_for(
            "openai",
            {"input_tokens": 2_000_000, "output_tokens": 0, "cached_tokens": 0},
        )
        == 2_000_000
    )
    assert (
        registry.cost_for(
            "openai",
            {
                "input_tokens": 1_000_000,
                "output_tokens": 100_000,
                "cached_tokens": 200_000,
                "cache_write_tokens": 100_000,
            },
        )
        == 1_460_000
    )
    # Legacy usage without the write subset still prices (zero writes).
    assert (
        registry.cost_for(
            "openai",
            {"input_tokens": 1_000_000, "output_tokens": 0, "cached_tokens": 1_000_000},
        )
        == 50_000
    )


def test_gemini_cost_flash_intro_rates():
    # 3.8 Flash paid intro (through 2026-12-31): .75/.075/3.75 per M,
    # output includes thoughts.
    assert (
        registry.cost_for(
            "gemini",
            {"input_tokens": 1_000_000, "output_tokens": 0, "cached_tokens": 0},
        )
        == 750_000
    )
    assert (
        registry.cost_for(
            "gemini",
            {"input_tokens": 1_000_000, "output_tokens": 100_000, "cached_tokens": 200_000},
        )
        == 990_000
    )


def test_anthropic_cost_flat_sonnet_and_disjoint_caches():
    # Flat Sonnet rate (no tier): 2.00/10.00/0.10 per M, 5m writes
    # 2.50, 1h/unknown writes 4.00. The adapter reports input_tokens
    # as the disjoint total (base+created+read). 90k base + 10k
    # unknown creation + 1k output = 180000 + 40000 + 10000 micro-USD.
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
        == 230_000
    )
    # Explicit 5-minute creation bills at its own rate: 90k base
    # + 10k 5m creation + 1k output = 180000 + 25000 + 10000 micro-USD.
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
        == 215_000
    )
    # Reads bill at the cached rate: 90k base + 10k read =
    # 180000 + 1000 micro-USD.
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
        == 181_000
    )
    # Large prompts use the same flat rate (no tier): 100001 base =
    # 200002 micro-USD.
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
        == 200_002
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


def test_step_caps_cover_every_supported_usage_composition():
    """The per-step reservation bounds each provider's priciest mix.

    OpenAI writes and Anthropic creation bill above the plain input
    rate, so the caps reserve the whole input bound at the worst-case
    write/creation rate. Every composition below must fit.
    """
    input_upper = 1_000
    max_out = 100
    openai_cap = registry.step_cap_for("openai", input_upper=input_upper, max_output_tokens=max_out)
    from app.ai.providers import openai_responses

    framing = openai_responses.WIRE_FRAMING_TOKENS
    total = input_upper + framing
    # Worst case: the whole input bound is cache-write.
    assert openai_cap == openai_responses.cost_micro_usd(
        input_tokens=total,
        cached_tokens=0,
        output_tokens=max_out,
        cache_write_tokens=total,
    )
    for cached, write in ((0, 0), (total, 0), (0, total), (300, 400), (700, 300)):
        assert openai_cap >= registry.cost_for(
            "openai",
            {
                "input_tokens": total,
                "output_tokens": max_out,
                "cached_tokens": cached,
                "cache_write_tokens": write,
            },
        )
    anthropic_cap = registry.step_cap_for(
        "anthropic", input_upper=input_upper, max_output_tokens=max_out
    )
    for five, one_h, read in (
        (0, 0, 0),
        (total, 0, 0),
        (0, total, 0),
        (0, 0, total),
        (200, 300, 100),
    ):
        base = total - five - one_h - read
        assert anthropic_cap >= registry.cost_for(
            "anthropic",
            {
                # The adapter reports the disjoint total; the
                # registry decomposes it back into buckets.
                "input_tokens": total,
                "output_tokens": max_out,
                "cached_tokens": read,
                "cache_creation_tokens": 0,
                "cache_creation_5m_tokens": five,
                "cache_creation_1h_tokens": one_h,
                "reasoning_tokens": 0,
            },
        )
        assert base >= 0


def test_unknown_provider_cost_fails_closed():
    with pytest.raises((KeyError, ValueError)):
        registry.cost_for("nope", {"input_tokens": 1, "output_tokens": 1})

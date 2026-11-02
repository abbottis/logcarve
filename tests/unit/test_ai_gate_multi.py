"""Multi-provider gate unit tests: tiers, policies, synthetic mode.

Pure offline tests: no network, no keys, no provider account.
"""

from types import SimpleNamespace

import pytest

from app.ai import gate
from app.ai.gate import GateBlocked


def _settings(provider, model, tier, verified=False, allow=False, **extra):
    return SimpleNamespace(
        model_provider=provider,
        model_id=model,
        model_service_tier=tier,
        model_data_policy_verified=verified,
        model_allow_real_data=allow,
        **extra,
    )


@pytest.mark.parametrize(
    "provider,model,tier",
    [
        ("meta", "muse-spark-1.3", "standard"),
        ("openai", "gpt-6-luna", "standard"),
        ("gemini", "gemini-3.5-flash-lite", "paid"),
        ("anthropic", "claude-haiku-5-5", "api"),
    ],
)
def test_all_providers_pass_with_matching_tier(provider, model, tier):
    decision = gate.validate_for_real_data(
        _settings(provider, model, tier, verified=True, allow=True)
    )
    assert (decision.provider, decision.model, decision.tier) == (provider, model, tier)


def test_tiers_are_never_relabeled():
    # Gemini Paid/API and Anthropic API must not pass as Meta Standard.
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("gemini", "gemini-3.5-flash-lite", "standard", verified=True, allow=True)
        )
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("anthropic", "claude-haiku-5-5", "standard", verified=True, allow=True)
        )
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("meta", "muse-spark-1.3", "paid", verified=True, allow=True)
        )


def test_unknown_provider_and_model_fail_closed():
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("unknown", "gpt-6-luna", "standard", verified=True, allow=True)
        )
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("openai", "muse-spark-1.3", "standard", verified=True, allow=True)
        )
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("meta", "gpt-6-luna", "standard", verified=True, allow=True)
        )


def test_unverified_policy_and_disabled_real_data_block():
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("openai", "gpt-6-luna", "standard", verified=False, allow=True)
        )
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(
            _settings("openai", "gpt-6-luna", "standard", verified=True, allow=False)
        )


def test_contributor_free_and_unknown_modes_are_blocked():
    # The exact reported boundary: an explicitly configured
    # Contributor/free/unknown mode is never an allowed mode, even
    # with a verified policy acknowledgment.
    for tier in ("contributor", "free", "unknown", ""):
        with pytest.raises(GateBlocked):
            gate.validate_for_real_data(
                _settings(
                    "meta",
                    "muse-spark-1.3",
                    tier,
                    verified=True,
                    allow=True,
                )
            )
        with pytest.raises(GateBlocked):
            gate.validate_for_synthetic(
                _settings(
                    "meta",
                    "muse-spark-1.3",
                    tier,
                    synthetic_only=True,
                    synthetic_source_asserted=True,
                )
            )


def test_unreadable_store_blocks_both_gates():
    # A corrupt/unreadable settings store fails AI closed while
    # deterministic analytics stay online (no exception type leaks).
    settings = _settings(
        "meta",
        "muse-spark-1.3",
        "standard",
        verified=True,
        allow=True,
        ai_store_error="settings_unavailable",
    )
    with pytest.raises(GateBlocked) as real_exc:
        gate.validate_for_real_data(settings)
    assert real_exc.value.code == "settings_unavailable"
    with pytest.raises(GateBlocked) as synth_exc:
        gate.validate_for_synthetic(
            _settings(
                "meta",
                "muse-spark-1.3",
                "standard",
                synthetic_only=True,
                synthetic_source_asserted=True,
                ai_store_error="settings_unavailable",
            )
        )
    assert synth_exc.value.code == "settings_unavailable"


def test_synthetic_mode_requires_explicit_selection_and_assertion():
    settings = _settings(
        "gemini",
        "gemini-3.5-flash-lite",
        "paid",
        synthetic_only=True,
        synthetic_source_asserted=True,
    )
    decision = gate.validate_for_synthetic(settings)
    assert decision.provider == "gemini"
    # Real gate still blocks: synthetic mode is not a real-data bypass.
    with pytest.raises(GateBlocked):
        gate.validate_for_real_data(settings)
    without_assertion = _settings(
        "gemini",
        "gemini-3.5-flash-lite",
        "paid",
        synthetic_only=True,
        synthetic_source_asserted=False,
    )
    with pytest.raises(GateBlocked):
        gate.validate_for_synthetic(without_assertion)
    unset_mode = _settings("gemini", "gemini-3.5-flash-lite", "paid")
    with pytest.raises(GateBlocked):
        gate.validate_for_synthetic(unset_mode)

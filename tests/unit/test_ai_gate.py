"""T7 gate tests: allowlisted provider/model/tier pass, everything else fails closed."""

import pytest

from app.ai import gate
from app.config import Settings


def _settings(**overrides):
    base = {
        "ai_enabled": True,
        "model_provider": "meta",
        "model_id": "muse-spark-1.3",
        "model_service_tier": "standard",
        "model_data_policy_verified": True,
        "model_allow_real_data": True,
    }
    base.update(overrides)
    return Settings(**base)


def test_allowlisted_standard_configuration_passes():
    decision = gate.validate_for_real_data(_settings())
    assert (decision.provider, decision.model, decision.tier) == (
        "meta",
        "muse-spark-1.3",
        "standard",
    )


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("model_provider", "other", "unknown_provider"),
        ("model_provider", "", "unknown_provider"),
        ("model_id", "muse-wonder-1.0", "unapproved_model"),
        ("model_service_tier", "contributor", "unverified_tier"),
        ("model_service_tier", "standard-plus", "unverified_tier"),
        ("model_service_tier", "", "unverified_tier"),
    ],
)
def test_unallowlisted_values_fail_closed(field, value, code):
    with pytest.raises(gate.GateBlocked) as excinfo:
        gate.validate_for_real_data(_settings(**{field: value}))
    assert excinfo.value.code == code


def test_unverified_policy_or_disabled_flag_blocks_real_data():
    with pytest.raises(gate.GateBlocked) as excinfo:
        gate.validate_for_real_data(_settings(model_data_policy_verified=False))
    assert excinfo.value.code == "unverified_data_policy"
    with pytest.raises(gate.GateBlocked) as excinfo:
        gate.validate_for_real_data(_settings(model_allow_real_data=False))
    assert excinfo.value.code == "real_data_not_allowed"


def test_mid_session_tier_switch_is_revalidated():
    settings = _settings()
    assert gate.validate_for_real_data(settings).tier == "standard"
    settings.model_service_tier = "contributor"
    with pytest.raises(gate.GateBlocked) as excinfo:
        gate.validate_for_real_data(settings)
    assert excinfo.value.code == "unverified_tier"

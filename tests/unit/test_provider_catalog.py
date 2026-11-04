"""Provider catalog unit tests: vetted pairs, labels, exact endpoints.

Pure offline tests: no network, no keys, no provider account.
"""

import pytest

from app.ai import catalog, registry


def test_provider_ids_stable_order():
    assert catalog.provider_ids() == ("meta", "openai", "gemini", "anthropic")


def test_display_labels_have_no_underscores():
    for provider in catalog.provider_ids():
        label = catalog.provider_label(provider)
        assert "_" not in label
        assert label
    assert catalog.provider_label("meta") == "Meta"
    assert catalog.provider_label("openai") == "OpenAI"
    assert catalog.provider_label("gemini") == "Google Gemini"
    assert catalog.provider_label("anthropic") == "Anthropic Claude"


def test_vetted_models_only():
    assert catalog.models_for("meta") == ("muse-spark-1.3",)
    assert catalog.models_for("openai") == ("gpt-6.1-terra",)
    assert catalog.models_for("gemini") == ("gemini-3.8-flash",)
    assert catalog.models_for("anthropic") == ("claude-sonnet-5-5",)
    assert catalog.default_model("openai") == "gpt-6.1-terra"
    entry = catalog.validate_pair("gemini", "gemini-3.8-flash")
    assert entry.tier == "paid"
    assert catalog.CATALOG["anthropic"].tier == "api"
    assert catalog.CATALOG["meta"].tier == "standard"
    assert catalog.CATALOG["openai"].tier == "standard"


def test_unknown_pairs_fail_closed():
    with pytest.raises(KeyError):
        catalog.provider_label("nope")
    with pytest.raises(KeyError):
        catalog.models_for("nope")
    with pytest.raises((KeyError, ValueError)):
        catalog.validate_pair("meta", "gpt-6.1-terra")
    with pytest.raises((KeyError, ValueError)):
        catalog.validate_pair("openai", "muse-spark-1.3")
    with pytest.raises((KeyError, ValueError)):
        catalog.validate_pair("gemini", "claude-sonnet-5-5")
    with pytest.raises((KeyError, ValueError)):
        catalog.validate_pair("anthropic", "gpt-6.1-terra")
    with pytest.raises((KeyError, ValueError)):
        registry.entry_for("nope")
    with pytest.raises((KeyError, ValueError)):
        registry.endpoint_for("meta", "gpt-6.1-terra")


def test_exact_native_endpoints():
    assert registry.endpoint_for("meta", "muse-spark-1.3") == "https://api.meta.ai:443/v1/responses"
    assert (
        registry.endpoint_for("openai", "gpt-6.1-terra")
        == "https://api.openai.com:443/v1/responses"
    )
    assert (
        registry.endpoint_for("gemini", "gemini-3.8-flash")
        == "https://generativelanguage.googleapis.com:443/v1beta/models/"
        "gemini-3.8-flash:generateContent"
    )
    assert (
        registry.endpoint_for("anthropic", "claude-sonnet-5-5")
        == "https://api.anthropic.com:443/v1/messages"
    )


def test_real_adapter_names_cover_all_four():
    names = registry.real_adapter_names()
    assert names == frozenset(
        {
            "meta-responses",
            "openai-responses",
            "gemini-generate-content",
            "anthropic-messages",
        }
    )

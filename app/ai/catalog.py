"""Vetted provider/model catalog for product inference (ADR 0004).

One entry per supported provider with its display label (no
underscores), allowlisted models, exact trusted native HTTPS endpoint
policy, service-tier label and verified per-million-USD pricing with
provenance. Unknown provider/model combinations are rejected before
any dispatch; there is no arbitrary endpoint surface.

Pricing is verified per model (integer micro-USD arithmetic lives in
each adapter). Gemini Paid/API and Anthropic API tiers are labeled as
such and never as Meta Standard.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModelEntry:
    model_id: str
    pricing_version: str
    pricing_url: str


@dataclass(frozen=True)
class ProviderEntry:
    provider: str
    label: str
    endpoint_host: str
    endpoint_port: int
    endpoint_path: str
    tier: str
    models: tuple = field(default_factory=tuple)
    default_model: str = ""


CATALOG: dict[str, ProviderEntry] = {
    "meta": ProviderEntry(
        provider="meta",
        label="Meta",
        endpoint_host="api.meta.ai",
        endpoint_port=443,
        endpoint_path="/v1/responses",
        tier="standard",
        models=(
            ModelEntry(
                model_id="muse-spark-1.3",
                pricing_version="2026-10-31-dev.meta.ai",
                pricing_url="https://dev.meta.ai/docs/pricing-rate-limits",
            ),
        ),
        default_model="muse-spark-1.3",
    ),
    "openai": ProviderEntry(
        provider="openai",
        label="OpenAI",
        endpoint_host="api.openai.com",
        endpoint_port=443,
        endpoint_path="/v1/responses",
        tier="standard",
        models=(
            ModelEntry(
                model_id="gpt-6.1-terra",
                pricing_version="2026-11-02-developers.openai.com",
                pricing_url="https://developers.openai.com/api/docs/models/gpt-6.1-terra",
            ),
        ),
        default_model="gpt-6.1-terra",
    ),
    "gemini": ProviderEntry(
        provider="gemini",
        label="Google Gemini",
        endpoint_host="generativelanguage.googleapis.com",
        endpoint_port=443,
        endpoint_path="/v1beta/models",
        tier="paid",
        models=(
            ModelEntry(
                model_id="gemini-3.8-flash",
                pricing_version="2026-11-02-ai.google.dev",
                pricing_url="https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash",
            ),
        ),
        default_model="gemini-3.8-flash",
    ),
    "anthropic": ProviderEntry(
        provider="anthropic",
        label="Anthropic Claude",
        endpoint_host="api.anthropic.com",
        endpoint_port=443,
        endpoint_path="/v1/messages",
        tier="api",
        models=(
            ModelEntry(
                model_id="claude-sonnet-5-5",
                pricing_version="2026-11-02-platform.claude.com",
                pricing_url="https://platform.claude.com/docs/en/models/sonnet-5-5/overview",
            ),
        ),
        default_model="claude-sonnet-5-5",
    ),
}

#: Adapter names registered for real dispatches. The service treats
#: exactly these as real; anything else (fake/scripted) keeps
#: planning-estimate accounting and never requires keys or endpoints.
REAL_ADAPTER_NAMES = frozenset(
    {
        "meta-responses",
        "openai-responses",
        "gemini-generate-content",
        "anthropic-messages",
    }
)


def provider_ids() -> tuple[str, ...]:
    """Supported provider IDs in stable display order."""
    return ("meta", "openai", "gemini", "anthropic")


def provider_label(provider: str) -> str:
    """Display label without underscores; unknown providers fail closed."""
    entry = CATALOG.get(provider)
    if entry is None:
        raise KeyError(f"unknown provider: {provider!r}")
    return entry.label


def models_for(provider: str) -> tuple[str, ...]:
    """Allowlisted model IDs for one provider; unknown providers fail closed."""
    entry = CATALOG.get(provider)
    if entry is None:
        raise KeyError(f"unknown provider: {provider!r}")
    return tuple(model.model_id for model in entry.models)


def default_model(provider: str) -> str:
    """Default model for one provider; unknown providers fail closed."""
    entry = CATALOG.get(provider)
    if entry is None:
        raise KeyError(f"unknown provider: {provider!r}")
    return entry.default_model


def validate_pair(provider: str, model: str) -> ProviderEntry:
    """Return the catalog entry for an allowlisted pair, else fail closed."""
    entry = CATALOG.get(provider)
    if entry is None:
        raise ValueError(f"unknown provider: {provider!r}")
    if model not in {model.model_id for model in entry.models}:
        raise ValueError(f"unapproved model: {model!r}")
    return entry

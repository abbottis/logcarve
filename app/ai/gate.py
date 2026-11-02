"""Fail-closed provider/model/tier gate (T7, extended ADR 0004).

Validated before every attempted provider request, including tier or
mode changes mid-session: the gate reads the current effective
settings on each call, so a switch takes effect on the next request.
Unknown providers, unapproved models, unverified tiers, unverified
data policy or a disabled real-data flag all block real-data
transmission. An account flag or model ID alone never proves
effective handling.

Tier labels are provider-specific and never relabeled: Meta and
OpenAI run the ``standard`` tier, Gemini runs ``paid`` API handling
and Anthropic runs ``api`` handling. Google free, unknown or
unverified handling stays blocked because real-data mode requires
the provider-specific explicit acknowledgment recorded in effective
settings.
"""

from dataclasses import dataclass

from app.ai import catalog

ALLOWED_PROVIDERS = frozenset(catalog.provider_ids())
ALLOWED_TIERS = frozenset({"standard", "paid", "api"})


def allowed_models(provider: str) -> frozenset:
    """Allowlisted model IDs for one provider; unknown fails closed."""
    try:
        return frozenset(catalog.models_for(provider))
    except KeyError as exc:
        raise GateBlocked(
            "unknown_provider", "The configured model provider is not allowlisted."
        ) from exc


class GateBlocked(RuntimeError):
    """Real-data transmission is not permitted under current settings."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class GateDecision:
    provider: str
    model: str
    tier: str


def validate_for_real_data(settings) -> GateDecision:
    """Permit real-data egress under settings, else raise GateBlocked.

    Every field is re-read from the live effective settings object, so
    mid-session provider/model/tier/policy switches, replayed
    contexts and retries are revalidated rather than inheriting an
    earlier decision. Per-provider policy acknowledgments never
    transfer: the effective object already resolves the acknowledgment
    for its own provider only.
    """
    if str(getattr(settings, "ai_store_error", "") or ""):
        raise GateBlocked(
            "settings_unavailable",
            "The AI settings store is unavailable.",
        )
    provider = str(getattr(settings, "model_provider", ""))
    model = str(getattr(settings, "model_id", ""))
    tier = str(getattr(settings, "model_service_tier", ""))
    if provider not in ALLOWED_PROVIDERS:
        raise GateBlocked("unknown_provider", "The configured model provider is not allowlisted.")
    if model not in allowed_models(provider):
        raise GateBlocked("unapproved_model", "The configured model is not allowlisted.")
    if tier not in ALLOWED_TIERS:
        raise GateBlocked(
            "unverified_tier",
            "The effective service tier is not verified handling.",
        )
    expected_tier = catalog.CATALOG[provider].tier
    if tier != expected_tier:
        raise GateBlocked(
            "unverified_tier",
            "The effective service tier is not verified handling.",
        )
    if not bool(getattr(settings, "model_data_policy_verified", False)):
        raise GateBlocked(
            "unverified_data_policy",
            "The provider data policy is not verified for real data.",
        )
    if not bool(getattr(settings, "model_allow_real_data", False)):
        raise GateBlocked("real_data_not_allowed", "Real-data transmission is not enabled.")
    return GateDecision(provider=provider, model=model, tier=tier)


def validate_for_synthetic(settings) -> GateDecision:
    """Permit synthetic-only demo dispatch under explicit operator config.

    Requires the allowlisted provider/model/tier binding PLUS the
    explicit synthetic-only policy selection for this provider AND the
    operator trusted assertion that the imported source data is
    synthetic. Synthetic status is never inferred from client
    questions or URLs. Real-data mode stays blocked in this path:
    the decision carries no real-data permission.
    """
    if str(getattr(settings, "ai_store_error", "") or ""):
        raise GateBlocked(
            "settings_unavailable",
            "The AI settings store is unavailable.",
        )
    provider = str(getattr(settings, "model_provider", ""))
    model = str(getattr(settings, "model_id", ""))
    tier = str(getattr(settings, "model_service_tier", ""))
    if provider not in ALLOWED_PROVIDERS:
        raise GateBlocked("unknown_provider", "The configured model provider is not allowlisted.")
    if model not in allowed_models(provider):
        raise GateBlocked("unapproved_model", "The configured model is not allowlisted.")
    if tier not in ALLOWED_TIERS:
        raise GateBlocked(
            "unverified_tier",
            "The effective service tier is not verified handling.",
        )
    try:
        expected_tier = catalog.CATALOG[provider].tier
    except KeyError:
        raise GateBlocked(
            "unknown_provider", "The configured model provider is not allowlisted."
        ) from None
    if tier != expected_tier:
        raise GateBlocked(
            "unverified_tier",
            "The effective service tier is not verified handling.",
        )
    if not bool(getattr(settings, "synthetic_only", False)):
        raise GateBlocked("real_data_not_allowed", "Real-data transmission is not enabled.")
    if not bool(getattr(settings, "synthetic_source_asserted", False)):
        raise GateBlocked(
            "unverified_data_policy",
            "The synthetic source assertion is missing for demo mode.",
        )
    return GateDecision(provider=provider, model=model, tier=tier)

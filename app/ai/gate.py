"""Fail-closed provider/model/tier gate (T7).

Validated before every attempted provider request, including tier or
mode changes mid-session: the gate reads the current settings on each
call, so a switch takes effect on the next request. Unknown providers,
unapproved models, non-Standard tiers, unverified data policy or a
disabled real-data flag all block real-data transmission. An account
flag or model ID alone never proves effective Standard handling.
"""

from dataclasses import dataclass

ALLOWED_PROVIDERS = frozenset({"meta"})
ALLOWED_MODELS = frozenset({"muse-spark-1.3"})
ALLOWED_TIERS = frozenset({"standard"})


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

    Every field is re-read from the live settings object, so mid-session
    tier switches, replayed contexts and retries are revalidated rather
    than inheriting an earlier decision.
    """
    provider = str(getattr(settings, "model_provider", ""))
    model = str(getattr(settings, "model_id", ""))
    tier = str(getattr(settings, "model_service_tier", ""))
    if provider not in ALLOWED_PROVIDERS:
        raise GateBlocked("unknown_provider", "The configured model provider is not allowlisted.")
    if model not in ALLOWED_MODELS:
        raise GateBlocked("unapproved_model", "The configured model is not allowlisted.")
    if tier not in ALLOWED_TIERS:
        raise GateBlocked(
            "unverified_tier",
            "The effective service tier is not verified Standard handling.",
        )
    if not bool(getattr(settings, "model_data_policy_verified", False)):
        raise GateBlocked(
            "unverified_data_policy",
            "The provider data policy is not verified for real data.",
        )
    if not bool(getattr(settings, "model_allow_real_data", False)):
        raise GateBlocked("real_data_not_allowed", "Real-data transmission is not enabled.")
    return GateDecision(provider=provider, model=model, tier=tier)

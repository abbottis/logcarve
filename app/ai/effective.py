"""Effective AI settings: operator env base plus DB admin overlay (ADR 0004).

Resolution order per field is stored-DB first, then the operator env
fallback, so the current Meta env setup keeps working unchanged while
the backend Settings page can select providers, models, policies and
keys. Every resolution step fails closed: unknown providers/models,
unreadable keys or invalid values block provider dispatch without
breaking deterministic analytics.

Key sources per provider are ``stored`` (DB ciphertext decrypted with
``AI_SETTINGS_KEY``), ``env`` (operator environment fallback) or
``missing``. Removal is honest: deleting the stored key while an env
fallback exists reports ``env-managed`` instead of pretending the
provider is keyless. The resolved secret is held in memory only for
the current dispatch; only the source label and
configured/not-configured state ever reach settings pages, errors,
logs or exports.
"""

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import SecretStr

from app.ai import catalog, registry, settings_store
from app.ai.providers.base import ProviderError
from app.ai.settings_store import SettingsStoreError

TIER_LABELS = {
    "standard": "Standard",
    "paid": "Paid API",
    "api": "API",
}


@dataclass(frozen=True)
class EffectiveAISettings:
    """Resolved AI settings for one dispatch decision (in-memory only)."""

    ai_enabled: bool
    model_provider: str
    model_id: str
    model_service_tier: str
    model_data_policy_verified: bool
    model_allow_real_data: bool
    # Repr-safe secret storage: the generated repr/asdict never carry
    # plaintext key material (SecretStr masks on repr/str and asdict
    # keeps the wrapper, never the raw secret).
    model_api_key: SecretStr = field(repr=False)
    model_endpoint: str
    # Synthetic-only demo mode for this provider (explicit selection).
    synthetic_only: bool
    # Operator trusted assertion that the imported source data is
    # synthetic (never inferred from client questions or URLs).
    synthetic_source_asserted: bool
    # Per-provider policy selection: "" | "synthetic" | "real".
    ai_policy: str
    # Key provenance: "stored" | "env" | "missing".
    ai_key_source: str
    # True when a stored key row exists (even if unreadable).
    ai_key_stored: bool
    # True when a stored key exists but cannot be decrypted/read.
    ai_key_error: bool
    workspace_id: str
    # In-memory binding fingerprint (sha256 hex of the resolved key).
    key_fingerprint: str
    # Fixed code when the settings store itself is unreadable
    # (corrupt DB, I/O failure). AI dispatches fail closed while
    # deterministic analytics stay online. Empty when healthy.
    ai_store_error: str = ""
    # Budget and smoke caps pass through untouched from the operator
    # env base: settings saves never reset/clear/expand them.
    llm_daily_limit_usd: float = 0.0
    llm_stop_at_usd: float = 0.0
    llm_budget_usd: float = 0.0
    llm_warn_at_usd: float = 0.0
    smoke_max_investigations: int = 3
    smoke_max_requests: int = 12
    smoke_budget_usd: float = 1.0

    @property
    def provider_label(self) -> str:
        try:
            return catalog.provider_label(self.model_provider)
        except KeyError:
            return self.model_provider

    @property
    def tier_label(self) -> str:
        return TIER_LABELS.get(self.model_service_tier, self.model_service_tier)


def _overlay(db_path: Path) -> dict:
    """Read the raw DB overlay; empty only when genuinely never managed.

    ``{}`` is returned ONLY for an existing, readable store whose
    settings table exists but holds no ``ai.*`` rows (the backend was
    genuinely never managed). A missing store file, a missing
    settings table, or any corrupt/unreadable store raises a
    fixed-code :class:`SettingsStoreError`: callers fail AI closed
    while deterministic analytics stay online. Returning ``{}`` for a
    missing/deleted store or table would silently re-enable the env
    base after a configured backend disable/revocation became
    unreadable, so no ``except`` path here resolves to empty.
    """
    try:
        from app.db.database import connect

        conn = connect(Path(db_path), read_only=True)
    except Exception as exc:  # missing/unreadable store fails closed
        raise SettingsStoreError(
            "settings_unavailable", "The AI settings store is unavailable."
        ) from exc
    try:
        out: dict[str, str] = {}
        for key in (
            settings_store.ENABLED_SETTING,
            settings_store.PROVIDER_SETTING,
            settings_store.MODEL_SETTING,
            "ai.synthetic_source",
        ):
            value = settings_store.get_setting(conn, key)
            if value is not None:
                out[key] = value
        for provider in catalog.provider_ids():
            for prefix in (
                settings_store.POLICY_SETTING_PREFIX,
                settings_store.KEY_SETTING_PREFIX,
            ):
                value = settings_store.get_setting(conn, prefix + provider)
                if value is not None:
                    out[prefix + provider] = value
        workspace = settings_store.get_setting(conn, settings_store.WORKSPACE_SETTING)
        if workspace is not None:
            out[settings_store.WORKSPACE_SETTING] = workspace
        return out
    except SettingsStoreError:
        raise
    except Exception as exc:  # corrupt/missing tables fail closed, never empty
        raise SettingsStoreError(
            "settings_unavailable", "The AI settings store is unavailable."
        ) from exc
    finally:
        conn.close()


def _env_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _fail_closed(base, *, store_error: str) -> EffectiveAISettings:
    """Disabled effective settings when the store itself is unreadable.

    AI dispatches fail closed (the gate blocks on ``ai_store_error``);
    deterministic analytics stay online because this is still a plain
    value, never an exception.
    """

    def _num(name: str, default: float) -> float:
        try:
            return float(getattr(base, name, default))
        except (TypeError, ValueError):
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(getattr(base, name, default))
        except (TypeError, ValueError):
            return default

    return EffectiveAISettings(
        ai_enabled=False,
        model_provider=str(getattr(base, "model_provider", "meta") or "meta"),
        model_id=str(getattr(base, "model_id", "") or ""),
        model_service_tier=str(getattr(base, "model_service_tier", "") or ""),
        model_data_policy_verified=False,
        model_allow_real_data=False,
        model_api_key=SecretStr(""),
        model_endpoint="",
        synthetic_only=False,
        synthetic_source_asserted=False,
        ai_policy="",
        ai_key_source="missing",
        ai_key_stored=False,
        ai_key_error=False,
        workspace_id="",
        key_fingerprint="",
        ai_store_error=store_error,
        llm_daily_limit_usd=_num("llm_daily_limit_usd", 0.0),
        llm_stop_at_usd=_num("llm_stop_at_usd", 0.0),
        llm_budget_usd=_num("llm_budget_usd", 0.0),
        llm_warn_at_usd=_num("llm_warn_at_usd", 0.0),
        smoke_max_investigations=_int("smoke_max_investigations", 3),
        smoke_max_requests=_int("smoke_max_requests", 12),
        smoke_budget_usd=_num("smoke_budget_usd", 1.0),
    )


def resolve(db_path: Path, base) -> EffectiveAISettings:
    """Resolve effective settings from env base plus DB overlay."""
    try:
        overlay = _overlay(db_path)
    except SettingsStoreError as exc:
        return _fail_closed(base, store_error=exc.code)
    base_provider = str(getattr(base, "model_provider", "meta") or "meta")
    if settings_store.PROVIDER_SETTING in overlay:
        # A persisted provider row is authoritative verbatim — even
        # empty or unknown — so the gate rejects it: silently
        # replacing it with the env default would grant a different
        # provider's handling to stored config.
        provider = overlay[settings_store.PROVIDER_SETTING].strip()
    else:
        provider = base_provider
    provider_known = provider in catalog.CATALOG

    if settings_store.MODEL_SETTING in overlay:
        # A persisted model row is authoritative verbatim — even
        # empty — so a corrupt/blank row fails closed instead of
        # falling back to the env base model.
        model = overlay[settings_store.MODEL_SETTING].strip()
    elif provider_known and provider != base_provider:
        model = catalog.default_model(provider)
    elif provider == base_provider:
        model = str(getattr(base, "model_id", "") or "")
    else:
        # Unknown persisted provider without a stored model: nothing
        # safe to dispatch; the gate rejects the provider first.
        model = ""

    if settings_store.ENABLED_SETTING in overlay:
        enabled = overlay[settings_store.ENABLED_SETTING] == "1"
    else:
        enabled = bool(getattr(base, "ai_enabled", False))

    policy_key = settings_store.POLICY_SETTING_PREFIX + provider
    if policy_key in overlay:
        # A persisted policy row is authoritative: a present-but-empty
        # or invalid value is explicit UNACKNOWLEDGED (or corrupt) and
        # fails closed — it is never normalized away to resurrect the
        # legacy env permission below.
        raw_policy = overlay[policy_key].strip()
        if raw_policy in (settings_store.POLICY_SYNTHETIC, settings_store.POLICY_REAL):
            policy = raw_policy
        else:
            policy = ""
    else:
        # No policy row was ever saved for this provider: only then
        # may the backwards-compatible Meta env flags apply.
        policy = ""
        raw_policy = None

    synthetic_source_asserted = False
    if "ai.synthetic_source" in overlay:
        synthetic_source_asserted = overlay["ai.synthetic_source"] == "1"
    else:
        synthetic_source_asserted = _env_flag(getattr(base, "ai_synthetic_source", False))

    if policy == settings_store.POLICY_REAL:
        verified, allow_real = True, True
    elif policy == settings_store.POLICY_SYNTHETIC:
        verified, allow_real = False, False
    elif raw_policy is None and provider == "meta" and provider == base_provider:
        # Backwards-compatible Meta env flags (existing demo setup).
        # Only when no policy row was ever saved for this provider
        # and only for the same provider the operator configured: a
        # per-provider stored acknowledgment never transfers, and it
        # never overrides the effective service-tier mode (the gate
        # still requires the tier to match the catalog entry).
        verified = bool(getattr(base, "model_data_policy_verified", False))
        allow_real = bool(getattr(base, "model_allow_real_data", False))
    else:
        verified, allow_real = False, False

    if provider == base_provider:
        # The operator's explicit mode for THIS provider is
        # authoritative: a Contributor/free/unknown tier is preserved
        # verbatim so the gate blocks it instead of being relabeled
        # to the catalog tier.
        tier = str(getattr(base, "model_service_tier", "") or "")
    elif provider_known:
        tier = catalog.CATALOG[provider].tier
    else:
        tier = str(getattr(base, "model_service_tier", "") or "")

    # Key resolution: a stored row (even unreadable, even empty) is
    # authoritative for its provider — env fallback applies ONLY when
    # no stored row exists. Falling back after tamper would silently
    # resurrect a revoked key.
    secret = ""
    source = "missing"
    key_error = False
    stored_blob = overlay.get(settings_store.KEY_SETTING_PREFIX + provider)
    if stored_blob is not None:
        try:
            settings_key = settings_store.require_settings_key(
                getattr(base, "ai_settings_key", None)
            )
            secret = settings_store.decrypt_provider_key(provider, stored_blob, key=settings_key)
            source = "stored"
        except SettingsStoreError:
            key_error = True
            secret = ""
    else:
        env_name = settings_store.PROVIDER_ENV_KEYS.get(provider, "")
        candidate = ""
        if env_name:
            raw = getattr(base, _ENV_ATTR.get(provider, ""), None)
            if raw is None:
                import os

                candidate = os.environ.get(env_name, "")
            else:
                get_secret = getattr(raw, "get_secret_value", None)
                candidate = get_secret() if callable(get_secret) else raw
                if not isinstance(candidate, str):
                    candidate = ""
        if isinstance(candidate, str) and candidate:
            secret = candidate
            source = "env"

    try:
        endpoint = registry.endpoint_for(provider, model)
    except (KeyError, ValueError):
        endpoint = ""
    if provider == "meta":
        legacy_raw = getattr(base, "model_endpoint", "")
        legacy_secret = getattr(legacy_raw, "get_secret_value", None)
        legacy = legacy_secret() if callable(legacy_secret) else legacy_raw
        if isinstance(legacy, str) and legacy:
            endpoint = legacy

    workspace = overlay.get(settings_store.WORKSPACE_SETTING, "").strip()
    if not workspace:
        workspace = str(getattr(base, "anthropic_workspace_id", "") or "").strip()
    if not workspace:
        import os

        env_workspace = os.environ.get(settings_store.WORKSPACE_ENV, "") or ""
        workspace = env_workspace.strip() if isinstance(env_workspace, str) else ""
    try:
        from app.ai.providers import anthropic_messages

        workspace = anthropic_messages.validate_workspace_id(workspace)
    except (ProviderError, ValueError, TypeError):
        workspace = ""

    fingerprint = settings_store.key_fingerprint(secret) if secret else ""

    def _num(name: str, default: float) -> float:
        try:
            return float(getattr(base, name, default))
        except (TypeError, ValueError):
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(getattr(base, name, default))
        except (TypeError, ValueError):
            return default

    return EffectiveAISettings(
        ai_enabled=enabled,
        model_provider=provider,
        model_id=model,
        model_service_tier=tier,
        model_data_policy_verified=verified,
        model_allow_real_data=allow_real,
        model_api_key=SecretStr(secret),
        model_endpoint=endpoint,
        synthetic_only=policy == settings_store.POLICY_SYNTHETIC,
        synthetic_source_asserted=synthetic_source_asserted,
        ai_policy=policy,
        ai_key_source=source,
        ai_key_stored=stored_blob is not None,
        ai_key_error=key_error,
        workspace_id=workspace,
        key_fingerprint=fingerprint,
        llm_daily_limit_usd=_num("llm_daily_limit_usd", 0.0),
        llm_stop_at_usd=_num("llm_stop_at_usd", 0.0),
        llm_budget_usd=_num("llm_budget_usd", 0.0),
        llm_warn_at_usd=_num("llm_warn_at_usd", 0.0),
        smoke_max_investigations=_int("smoke_max_investigations", 3),
        smoke_max_requests=_int("smoke_max_requests", 12),
        smoke_budget_usd=_num("smoke_budget_usd", 1.0),
    )


_ENV_ATTR = {
    "meta": "model_api_key",
    "openai": "openai_api_key",
    "gemini": "gemini_api_key",
    "anthropic": "anthropic_api_key",
}


def key_statuses(db_path: Path, base) -> dict:
    """Per-provider key provenance without ever returning key material.

    Each entry carries ``stored`` (a DB ciphertext row exists),
    ``readable`` (it decrypts with the current ``AI_SETTINGS_KEY``)
    and ``env`` (an operator env fallback provides a key). The web
    layer maps these to configured / not-configured / env-managed
    states; undecryptable rows surface as stored-unreadable and fail
    closed at dispatch without breaking deterministic analytics.
    When the store itself is unreadable every provider reports no
    stored row (fail closed at dispatch via ``ai_store_error``).
    """
    try:
        overlay = _overlay(db_path)
    except SettingsStoreError:
        overlay = {}
    result: dict[str, dict] = {}
    try:
        settings_key: bytes | None = settings_store.require_settings_key(
            getattr(base, "ai_settings_key", None)
        )
    except SettingsStoreError:
        settings_key = None
    import os as _os

    for provider in catalog.provider_ids():
        stored_blob = overlay.get(settings_store.KEY_SETTING_PREFIX + provider)
        stored = bool(stored_blob)
        readable = False
        if stored and settings_key is not None:
            try:
                settings_store.decrypt_provider_key(provider, stored_blob, key=settings_key)
                readable = True
            except SettingsStoreError:
                readable = False
        env_name = settings_store.PROVIDER_ENV_KEYS.get(provider, "")
        env_present = False
        if env_name:
            raw = getattr(base, _ENV_ATTR.get(provider, ""), None)
            if raw is None:
                env_present = bool(_os.environ.get(env_name, ""))
            else:
                get_secret = getattr(raw, "get_secret_value", None)
                candidate = get_secret() if callable(get_secret) else raw
                env_present = isinstance(candidate, str) and bool(candidate)
        result[provider] = {"stored": stored, "readable": readable, "env": env_present}
    return result


def binding_of(settings: EffectiveAISettings) -> tuple:
    """Pinned per-investigation binding; any change fails closed.

    Pins provider, model, resolved key, policy flags, the enable
    switch AND the service tier, endpoint and workspace: a changed
    mode/workspace/endpoint must fail the next attempt, not just a
    changed provider/model/key/policy/enable flag.
    """
    return (
        settings.model_provider,
        settings.model_id,
        settings.key_fingerprint,
        settings.model_data_policy_verified,
        settings.model_allow_real_data,
        settings.synthetic_only,
        settings.synthetic_source_asserted,
        settings.ai_enabled,
        settings.model_service_tier,
        settings.model_endpoint,
        settings.workspace_id,
    )

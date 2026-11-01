"""Validated product configuration.

Field names match `.env.example`, the proposed runtime contract. Server
secrets are required and must be non-empty: the application fails
clearly at startup when they are absent instead of running with
insecure values. Product AI stays disabled until a later slice
explicitly enables it.
"""

from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_base_url: str = "https://logcarve.example.org"
    logcarve_log_paths: str = "/logs"
    database_path: str = "/data/logcarve.sqlite3"
    default_timezone: str = "UTC"
    retention_days: int = Field(default=30, ge=1)
    external_api_enabled: bool = True
    import_max_compressed_bytes: int = Field(default=1073741824, ge=1024)
    import_max_uncompressed_bytes: int = Field(default=1073741824, ge=1024)
    import_max_compression_ratio: float = Field(default=100.0, ge=1.0)
    import_max_gzip_members: int = Field(default=64, ge=1)
    import_autodetect_sample_lines: int = Field(default=32, ge=1, le=1024)

    session_secret: SecretStr = Field(min_length=1)
    hmac_key: SecretStr = Field(min_length=1)
    # Separate optional server key for T1b encrypted original-IP storage.
    # Never SESSION_SECRET/HMAC_KEY/MODEL_API_KEY; empty means capture and
    # private reads fail closed while deterministic analytics keep working.
    original_ip_key: SecretStr = SecretStr("")

    ai_enabled: bool = False
    model_provider: str = "meta"
    model_id: str = "muse-spark-1.3"
    model_service_tier: str = "standard"
    model_data_policy_verified: bool = False
    model_allow_real_data: bool = False
    model_api_key: SecretStr = SecretStr("")
    # Real Responses endpoint. Runtime default is EMPTY on purpose:
    # the operator supplies the allowlisted URL through validated
    # configuration; no fallback URL lives in application code.
    model_endpoint: str = ""
    # Lifetime smoke caps for the single capped T8 approval; tighter
    # existing budget limits bind alongside these.
    smoke_max_investigations: int = Field(default=3, ge=0)
    smoke_max_requests: int = Field(default=12, ge=0)
    smoke_budget_usd: float = Field(default=1.0, ge=0)

    llm_budget_usd: float = Field(default=150.0, ge=0)
    llm_warn_at_usd: float = Field(default=120.0, ge=0)
    llm_stop_at_usd: float = Field(default=140.0, ge=0)
    llm_daily_limit_usd: float = Field(default=0.0, ge=0)

    open_model_base_url: str = ""
    open_model_id: str = "meta-models/muse-spark-open-1026"
    open_model_api_key: SecretStr = SecretStr("")

    @field_validator("default_timezone")
    @classmethod
    def _validate_default_timezone(cls, value: str) -> str:
        """The display default must be an installed IANA key.

        This validates the configured server default only; per-request
        `tz` values are validated separately against the cached catalogue.
        A single `ZoneInfo` construction proves installability without
        enumerating the filesystem catalogue on every `Settings`
        construction (`load_settings` runs per request).
        """
        name = (value or "").strip()
        if not name:
            raise ValueError("default_timezone must be a valid IANA timezone name")
        try:
            ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
            raise ValueError(f"unknown timezone: {name}") from exc
        return name

    @model_validator(mode="after")
    def _budget_ordering(self) -> "Settings":
        if not self.llm_warn_at_usd <= self.llm_stop_at_usd <= self.llm_budget_usd:
            raise ValueError("require llm_warn_at_usd <= llm_stop_at_usd <= llm_budget_usd")
        return self


def load_settings() -> Settings:
    return Settings()

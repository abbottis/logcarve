"""Versioned bot/security rule set with documented provenance (T4).

Rules are data, not code: YAML files carry an ID, version, category,
matchers and a claim-only meaning. A User-Agent match proves a claimed
identity, never a verified one; security matches are investigation
candidates, never proof of compromise. Loaders validate every entry and
reject duplicates, so a typo can never silently broaden matching.
"""

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

RuleCategory = Literal[
    "search_crawler",
    "ai_crawler",
    "seo_tool",
    "monitoring",
    "generic_bot",
    "suspected_automation",
    "unknown",
    "social_bot",
    "federation_crawler",
    "feed_fetcher",
    "automation_tool",
    "sensitive_path",
    "repeated_client_errors",
    "conflicting_bot_identity",
]

ClaimSeverity = Literal["info", "candidate"]


class Rule(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    version: int = Field(ge=1)
    category: RuleCategory
    title: str = Field(min_length=1, max_length=200)
    meaning: str = Field(min_length=1, max_length=500)
    provider: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: str | None = Field(default=None, min_length=1, max_length=120)
    ua_contains: list[str] = Field(default_factory=list)
    ua_regex: list[str] = Field(default_factory=list)
    path_contains: list[str] = Field(default_factory=list)
    #: Row-level status allowlist (stored origin status codes). Combined
    #: with ``path_contains`` by conjunction: a row matches only when
    #: every set matcher holds. Never reconstructed from queries or raw
    #: lines — only the stored normalized status participates.
    status_in: list[int] = Field(default_factory=list)
    min_client_errors: int | None = Field(default=None, ge=1)
    #: Per-pseudonym rate rule: pseudonyms with at least this many
    #: matching rows (after ``path_contains``/``status_in`` narrowing)
    #: become one finding each. Counts only stored events; rejected
    #: lines never participate.
    min_client_requests: int | None = Field(default=None, ge=1)
    #: Per-pseudonym breadth rule: pseudonyms touching at least this
    #: many distinct matching paths become one finding each (probe
    #: sweep candidate, never proof of a scan).
    min_client_distinct_paths: int | None = Field(default=None, ge=1)
    conflicting_identities: bool = False
    severity: ClaimSeverity = "info"

    @field_validator("ua_contains", "ua_regex", "path_contains")
    @classmethod
    def _non_empty_matcher(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 256:
                raise ValueError("matchers must be 1..256 characters")
        return values

    @field_validator("status_in")
    @classmethod
    def _valid_status(cls, values: list[int]) -> list[int]:
        for value in values:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError("status_in entries must be integers")
            if value < 100 or value > 599:
                raise ValueError("status_in entries must be 100..599")
        if len(set(values)) != len(values):
            raise ValueError("status_in entries must be distinct")
        return values

    @field_validator("ua_regex")
    @classmethod
    def _compilable_regex(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid ua_regex {value!r}: {exc}") from exc
        return values

    @model_validator(mode="after")
    def _has_matcher(self) -> "Rule":
        if (
            not self.ua_contains
            and not self.ua_regex
            and not self.path_contains
            and not self.status_in
            and self.min_client_errors is None
            and self.min_client_requests is None
            and self.min_client_distinct_paths is None
            and not self.conflicting_identities
        ):
            raise ValueError(f"rule {self.id} needs at least one matcher")
        if self.conflicting_identities and (
            self.ua_contains
            or self.ua_regex
            or self.path_contains
            or self.status_in
            or self.min_client_errors is not None
            or self.min_client_requests is not None
            or self.min_client_distinct_paths is not None
        ):
            raise ValueError(f"rule {self.id}: conflicting_identities stands alone")
        return self

    def matches_ua(self, user_agent: str | None) -> bool:
        if not user_agent:
            return False
        if self.ua_contains:
            lowered = user_agent.lower()
            if any(fragment.lower() in lowered for fragment in self.ua_contains):
                return True
        return any(
            re.search(pattern, user_agent, re.IGNORECASE) is not None for pattern in self.ua_regex
        )

    def matches_path(self, path: str) -> bool:
        if not self.path_contains:
            return False
        lowered = path.lower()
        return any(fragment.lower() in lowered for fragment in self.path_contains)


class RuleSet(BaseModel):
    version: int = Field(ge=1)
    provenance: str = Field(min_length=1)
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique_ids(self) -> "RuleSet":
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return self


def load_rules(path: Path) -> RuleSet:
    """Load and validate one rule file; unknown file content is rejected."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"rule file must hold a mapping: {path}")
    return RuleSet.model_validate(data)

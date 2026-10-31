"""Versioned bot/security rule set with documented provenance (T4).

Rules are data, not code: YAML files carry an ID, version, category,
matchers and a claim-only meaning. A User-Agent match proves a claimed
identity, never a verified one; security matches are investigation
candidates, never proof of compromise. Loaders validate every entry and
reject duplicates, so a typo can never silently broaden matching.
"""

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
    "sensitive_path",
    "repeated_client_errors",
]

ClaimSeverity = Literal["info", "candidate"]


class Rule(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    version: int = Field(ge=1)
    category: RuleCategory
    title: str = Field(min_length=1, max_length=200)
    meaning: str = Field(min_length=1, max_length=500)
    ua_contains: list[str] = Field(default_factory=list)
    path_contains: list[str] = Field(default_factory=list)
    min_client_errors: int | None = Field(default=None, ge=1)
    severity: ClaimSeverity = "info"

    @field_validator("ua_contains", "path_contains")
    @classmethod
    def _non_empty_matcher(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 256:
                raise ValueError("matchers must be 1..256 characters")
        return values

    @model_validator(mode="after")
    def _has_matcher(self) -> "Rule":
        if not self.ua_contains and not self.path_contains and self.min_client_errors is None:
            raise ValueError(f"rule {self.id} needs at least one matcher")
        return self

    def matches_ua(self, user_agent: str | None) -> bool:
        if not self.ua_contains or not user_agent:
            return False
        lowered = user_agent.lower()
        return any(fragment.lower() in lowered for fragment in self.ua_contains)

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

"""T1 configuration tests: secret handling, AI-disabled default, budget
ordering and retention default. Synthetic values only; the autouse
fixture in `conftest.py` supplies secrets and an isolated cwd.
"""

import os

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_ai_disabled_by_default():
    assert Settings().ai_enabled is False


def test_ambient_ai_enabled_true_is_isolated():
    """Regression: ambient AI_ENABLED=true must not leak into tests."""
    assert os.getenv("AI_ENABLED") is None
    assert os.getenv("ai_enabled") is None
    assert Settings().ai_enabled is False


def test_ambient_llm_warn_at_usd_is_isolated():
    """Regression: ambient LLM_WARN_AT_USD=999 must not leak into tests."""
    assert os.getenv("LLM_WARN_AT_USD") is None
    assert os.getenv("llm_warn_at_usd") is None
    assert Settings().llm_warn_at_usd == 120.0


def test_missing_secrets_fail_clearly(monkeypatch):
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.delenv("HMAC_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings()


def test_empty_secrets_rejected(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "")
    monkeypatch.setenv("HMAC_KEY", "")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize(
    "warn,stop,budget",
    [
        (130.0, 100.0, 150.0),  # warn above stop
        (150.0, 140.0, 150.0),  # warn above stop at the budget edge
        (120.0, 200.0, 150.0),  # stop above budget
        (160.0, 170.0, 150.0),  # both above budget
    ],
)
def test_disordered_budgets_rejected(warn, stop, budget):
    with pytest.raises(ValidationError):
        Settings(
            llm_warn_at_usd=warn,
            llm_stop_at_usd=stop,
            llm_budget_usd=budget,
        )


def test_ordered_budget_accepted():
    settings = Settings(llm_warn_at_usd=120.0, llm_stop_at_usd=140.0, llm_budget_usd=150.0)
    assert settings.llm_warn_at_usd <= settings.llm_stop_at_usd <= settings.llm_budget_usd


def test_retention_default_is_thirty_days():
    assert Settings().retention_days == 30

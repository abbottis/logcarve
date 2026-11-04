"""Hermetic test environment for unit and integration tests.

Every test runs with synthetic server secrets and an isolated working
directory, so results never depend on ambient environment variables or
a developer's local `.env` file. pydantic-settings already prefers
real environment variables over `.env` entries; the isolated cwd
removes the file from the picture entirely, and clearing every
environment variable consumed by `Settings` removes the ambient
process environment. `monkeypatch` restores all of these after each
test, so production validation in `app/config.py` is untouched.
"""

import pytest

from app.config import Settings


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for field in Settings.model_fields:
        monkeypatch.delenv(field.upper(), raising=False)
        monkeypatch.delenv(field, raising=False)
    monkeypatch.setenv("SESSION_SECRET", "synthetic-test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "synthetic-test-hmac-key")

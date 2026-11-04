"""T1 startup tests: the composition root serves liveness with no model
credentials present and reports AI as disabled.

The application module is reloaded under the fixture's synthetic
environment so initialization never depends on ambient variables.
"""

import importlib

import pytest
from starlette.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SESSION_SECRET", "test-session-secret")
    monkeypatch.setenv("HMAC_KEY", "test-hmac-key")
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    import app.main as main_module

    reloaded = importlib.reload(main_module)
    return TestClient(reloaded.app, raise_server_exceptions=False)


def test_healthz_without_model_key(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "logcarve"
    assert body["ai_enabled"] is False

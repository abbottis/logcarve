"""E2E collection setup: project-local Playwright browsers.

The browser executable path must be visible before any browser-launch
fixture runs, so it is set here at collection time (absolute path into
ignored ``artifacts/``). Tests additionally scope it per-fixture.
"""

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / "artifacts" / "playwright-browsers"))


@pytest.fixture(scope="session")
def browser_type_launch_args():
    # Keep the OS/browser sandbox engaged for every test launch: no
    # --no-sandbox or equivalent weakening, here or anywhere else.
    # Coordinator-verified working invocation (project .venv, project
    # browsers, no protection changed): headless launch with
    # chromium_sandbox=True and a 15 s timeout. If the same protected
    # mode cannot run inside the enclosing shell sandbox, the suite
    # records BLOCKED with the actual error and the coordinator runs
    # the exact maintained command below outside that sandbox:
    #   uv run --locked pytest tests/e2e -q
    return {"chromium_sandbox": True, "timeout": 15000}

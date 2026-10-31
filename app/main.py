"""Minimal composition root (T5 API plus T9-A dashboard).

Exposes liveness, restricted readiness, the versioned read-only
analytics API with local admin session endpoints, and the
session-gated browser dashboard served from the shared analytics
layer. Importing this module never requires model credentials or
provider access.
"""

from pathlib import Path

from app.api.app import build_api
from app.config import load_settings

RULES_DIR = Path(__file__).resolve().parent.parent / "config"


def create_app(
    db_path: Path | str | None = None,
    rules_dir: Path | str | None = None,
    secure_cookies: bool | None = None,
    login_max_attempts: int = 10,
    login_window_s: float = 300.0,
):
    settings = load_settings()
    if secure_cookies is None:
        secure_cookies = settings.app_base_url.startswith("https://")
    return build_api(
        db_path=Path(settings.database_path) if db_path is None else Path(db_path),
        rules_dir=RULES_DIR if rules_dir is None else Path(rules_dir),
        secure_cookies=secure_cookies,
        login_max_attempts=login_max_attempts,
        login_window_s=login_window_s,
    )


app = create_app()

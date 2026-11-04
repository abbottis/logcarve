"""T9-A coordinator-review regressions (no browser needed).

Covers the review observations that must hold before freezing part A:
safe same-site redirects, theme-aware template tokens, a real menu
button, centralized browser strings, and the logout/CSRF-refresh
contract the client recovery path depends on. Synthetic data only.
"""

from pathlib import Path
from urllib.parse import unquote

from app.web.locales import t
from app.web.routes import _safe_next

ROOT = Path(__file__).resolve().parent.parent.parent


def test_safe_next_allows_in_site_paths():
    assert _safe_next("/") == "/"
    assert _safe_next("/?range=7d&tz=UTC") == "/?range=7d&tz=UTC"
    assert _safe_next("/login") == "/login"


def test_safe_next_rejects_external_and_control_shapes():
    assert _safe_next("//example.org/") == "/"
    assert _safe_next("/\\example.org/") == "/"
    assert _safe_next("https://example.org/") == "/"
    assert _safe_next("javascript:alert(1)") == "/"
    assert _safe_next("/a\nb") == "/"
    assert _safe_next("/a\rb") == "/"
    assert _safe_next("/a\tb") == "/"
    assert _safe_next("/a\x7fb") == "/"
    assert _safe_next("") == "/"
    assert _safe_next(None) == "/"


def test_login_redirect_encodes_full_target(web):
    client, _ = web
    target = "/?range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
    response = client.get(target, follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    encoded = location.split("next=", 1)[1]
    # Fully encoded: no raw query delimiters that would corrupt the
    # login URL, and decoding restores the exact original target.
    assert "?" not in encoded and "&" not in encoded
    assert unquote(encoded) == target


def test_templates_use_theme_aware_tokens():
    banned = ("bg-white", "bg-slate-50", "text-slate-900", "text-slate-600", "border-slate-200")
    offenders = []
    for path in (ROOT / "app" / "web" / "templates").rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            if token in text:
                offenders.append(f"{path.name}: {token}")
    assert offenders == []


def test_menu_is_a_real_button_with_state(web):
    client, _ = web
    client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    html = client.get("/").text
    assert '<button id="nav-button"' in html
    assert "aria-expanded=" in html
    assert 'aria-controls="side-nav"' in html
    assert 'for="nav-toggle"' not in html


def test_browser_strings_come_from_the_catalog(web):
    client, _ = web
    html = client.get("/login").text
    for key in (
        "auth.login.generic_error",
        "auth.login.rate_limited",
        "auth.login.unavailable",
        "auth.login.network_error",
    ):
        assert t(key) in html
    overview = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert overview.status_code == 200
    authed = client.get("/").text
    assert t("auth.logout.failed") in authed
    source = (ROOT / "assets" / "src" / "js" / "session.js").read_text(encoding="utf-8")
    for key in (
        "auth.login.generic_error",
        "auth.login.rate_limited",
        "auth.login.unavailable",
        "auth.login.network_error",
        "auth.logout.failed",
    ):
        assert t(key) not in source


def test_csrf_refresh_and_logout_denial_contract(web):
    client, _ = web
    assert client.get("/api/v1/admin/csrf").status_code == 401
    login = client.post("/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"})
    assert login.status_code == 200
    refresh = client.get("/api/v1/admin/csrf")
    assert refresh.status_code == 200
    assert refresh.json()["csrf_token"] == login.json()["csrf_token"]
    denied = client.post("/api/v1/admin/logout", headers={"X-CSRF-Token": "stale-token"})
    assert denied.status_code == 403
    assert denied.json()["code"] == "csrf_required"
    # The session survives the denied attempt: dashboard still renders.
    assert client.get("/").status_code == 200

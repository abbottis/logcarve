"""T9-A correction regressions for review findings A1–A5 (no browser needed).

A1: htmx hardening is declared in the meta config and indicator CSS is
    served locally (console-error proof itself needs the browser run).
A2: datetime-local values are normalized; fragments push the canonical
    page URL instead of the fragment endpoint.
A3: private HTML is no-store; stale sessions stay denied after logout.
A4: navigation is an overlay panel with a compact header.
A5: icons resolve to inlined theme-aware markup; no hardcoded surfaces.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def _meta_config(html: str) -> dict:
    match = re.search(r'<meta name="htmx-config" content=\'([^\']+)\'>', html)
    assert match, "htmx-config meta tag missing"
    return json.loads(match.group(1))


def test_htmx_config_disables_eval_styles_history_cache(web):
    client, _ = web
    config = _meta_config(client.get("/login").text)
    assert config["allowEval"] is False
    assert config["includeIndicatorStyles"] is False
    assert "style" not in config["attributesToSettle"]
    assert {"class", "width", "height"} <= set(config["attributesToSettle"])
    assert config["historyCacheSize"] == 0
    assert config["refreshOnHistoryMiss"] is True


def test_indicator_and_icon_css_is_local():
    css = (ROOT / "app" / "web" / "static" / "app.css").read_text(encoding="utf-8")
    assert ".htmx-indicator" in css
    assert ".lc-icon" in css


def test_fragment_pushes_canonical_page_url(web):
    client, _ = web
    _login(client)
    response = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=UTC")
    assert response.status_code == 200
    push = response.headers.get("hx-push-url", "")
    assert push.startswith("/?"), push
    assert "/partials" not in push
    for key in ("site=default", "range=custom", "from=2026-10-27", "to=2026-10-28", "tz=UTC"):
        assert key in push, push


def test_datetime_local_values_are_normalized(web):
    client, _ = web
    _login(client)
    html = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    values = re.findall(r'type="datetime-local" value="([^"]*)"', html)
    assert len(values) == 2
    assert values == ["2026-10-27T00:00", "2026-10-28T00:00"]
    for value in values:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", value)


def test_preset_window_prefills_normalized_values(web):
    client, _ = web
    _login(client)
    html = client.get("/").text
    values = re.findall(r'type="datetime-local" value="([^"]*)"', html)
    assert len(values) == 2
    for value in values:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", value), value


def test_fragment_refreshes_observation_window(web):
    client, _ = web
    _login(client)
    full = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    assert "data-observation-window" in full
    assert "2026-10-27T00:00:00+00:00" in full
    fragment = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=UTC").text
    assert "data-observation-window" in fragment
    assert "2026-10-27T00:00:00+00:00" in fragment
    assert "2026-10-28T00:00:00+00:00" in fragment


def test_intrinsic_width_guards_present():
    css = (ROOT / "app" / "web" / "static" / "app.css").read_text(encoding="utf-8")
    for rule in (".card", ".card-body", ".stats", ".stat", ".chart-frame", ".table-scroll"):
        assert rule in css
    assert "min-width: 0" in css or "min-width:0" in css
    assert ".chart-frame canvas" in css
    templates = ROOT / "app" / "web" / "templates"
    content = (templates / "partials" / "overview_content.html").read_text(encoding="utf-8")
    assert content.count("table-scroll overflow-x-auto") >= 4
    assert "overflow: hidden" not in (ROOT / "assets" / "src" / "css" / "app.css").read_text(
        encoding="utf-8"
    )


def test_private_html_is_no_store_but_static_is_not(web):
    client, _ = web
    assert client.get("/login").headers["cache-control"] == "no-store"
    _login(client)
    assert client.get("/").headers["cache-control"] == "no-store"
    fragment = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=UTC")
    assert fragment.headers["cache-control"] == "no-store"
    static = client.get("/static/app.css")
    assert static.status_code == 200
    assert "no-store" not in static.headers.get("cache-control", "")


def test_stale_session_fragment_stays_denied_after_logout(web):
    client, _ = web
    csrf = _login(client)
    session_cookie = client.cookies.get("lc_admin_session")
    assert session_cookie
    assert client.post("/api/v1/admin/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    # Replay the now-destroyed session cookie against the fragment endpoint.
    client.cookies.set("lc_admin_session", session_cookie)
    assert client.get("/partials/overview").status_code == 401
    assert client.get("/", follow_redirects=False).status_code == 302


def test_overlay_nav_and_compact_theme_select(web):
    client, _ = web
    _login(client)
    html = client.get("/").text
    assert 'id="nav-backdrop"' in html
    assert "fixed inset-y-0 left-0" in html
    assert "data-theme-select" in html
    assert 'id="theme-select"' in html


def test_template_icons_are_inlined_and_clean():
    templates = ROOT / "app" / "web" / "templates"
    used = set()
    for path in list(templates.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        assert "static/icons" not in text, f"{path.name} still loads icons via <img>"
        for match in re.findall(r'{% include "(icons/[^"]+\.svg)"', text):
            used.add(match)
        for match in re.findall(r'{% include "icons/" ~ .*? ~ "\.svg" %}', text):
            used.add("dynamic-subset")
    assert used, "no icon includes found"
    for name in (
        "layout-dashboard",
        "shield-alert",
        "bot",
        "circle-alert",
        "sparkles",
        "settings",
        "database",
        "log-in",
        "log-out",
        "menu",
    ):
        assert (templates / "icons" / f"{name}.svg").is_file(), name
    for name in sorted(used - {"dynamic-subset"}):
        svg = (templates / name).read_text(encoding="utf-8")
        assert svg.startswith("<svg")
        assert "{{" not in svg and "{%" not in svg
        root_tag = svg.split(">", 1)[0]
        assert 'class="lc-icon' in root_tag
        assert 'aria-hidden="true"' in root_tag
        assert ' width="' not in root_tag and ' height="' not in root_tag

"""Timezone notice uniqueness and effective-default consistency (web).

Full pages include the filter-bar notice exactly once: data partials
carry the same notice as a single out-of-band update, so an initial
page must never render two identical IDs. The effective server default
(unset configuration plus trusted regional TZ) orders the option list
and labels Settings identically. Synthetic data only.
"""

import re

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"

DATA_PAGES = ("/", "/security", "/crawlers", "/errors", "/requests")
DATA_PARTIALS = (
    "/partials/overview",
    "/partials/security",
    "/partials/crawlers",
    "/partials/errors",
    "/partials/requests",
)


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def _tz_select(page_html):
    match = re.search(r'<select id="f-tz".*?</select>', page_html, re.DOTALL)
    assert match, "native timezone select must render"
    return match.group(0)


def _option_values(select_html):
    return re.findall(r'<option value="([^"]+)"', select_html)


def _selected(select_html):
    match = re.search(r'<option value="([^"]+)" selected>', select_html)
    assert match, "one zone must read selected"
    return match.group(1)


def test_full_pages_carry_exactly_one_notice(web):
    """Every data page renders the filter-bar notice once, never doubled."""
    client, _ = web
    _login(client)
    for path in DATA_PAGES:
        page = client.get(f"{path}?site=default&{WINDOW_QS}&tz=UTC").text
        assert page.count('id="filter-times-notice"') == 1, path
        notice = re.search(r'<p id="filter-times-notice".*?</p>', page, re.DOTALL)
        assert notice, path
        assert "hx-swap-oob" not in notice.group(0), f"{path}: full page owns its notice"


def test_partials_carry_exactly_one_oob_notice(web):
    """Every data partial carries one out-of-band notice update."""
    client, _ = web
    _login(client)
    for partial in DATA_PARTIALS:
        response = client.get(f"{partial}?site=default&{WINDOW_QS}&tz=Asia%2FTokyo")
        assert response.status_code == 200, partial
        assert response.text.count('id="filter-times-notice"') == 1, partial
        assert "hx-swap-oob" in response.text, partial
        assert "Times shown in Asia/Tokyo" in response.text, partial


def test_apply_failure_carries_no_notice_update(web):
    """A failed Apply carries no notice: the stale notice stays put."""
    client, _ = web
    _login(client)
    for partial in DATA_PARTIALS:
        bad = client.get(f"{partial}?site=default&{WINDOW_QS}&tz=Nope%2FZone")
        assert bad.status_code == 400, partial
        assert bad.text.count('id="filter-times-notice"') == 0, partial


def test_unset_config_trusted_tz_orders_first_and_labels_settings(web, monkeypatch):
    """Unset config + TZ=Asia/Tokyo: Tokyo leads, selects, and labels Settings."""
    client, _ = web
    _login(client)
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    page = client.get(f"/requests?site=default&{WINDOW_QS}").text
    values = _option_values(_tz_select(page))
    assert values[0] == "Asia/Tokyo", "effective default orders first, not UTC"
    assert _selected(_tz_select(page)) == "Asia/Tokyo"
    settings = client.get("/settings").text
    assert ">Asia/Tokyo</dd>" in settings, "Settings shows the same effective default"


def test_explicit_url_wins_without_changing_configured_order(web, monkeypatch):
    """An explicit tz URL still wins selection while order follows the default."""
    client, _ = web
    _login(client)
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    page = client.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    values = _option_values(_tz_select(page))
    assert values[0] == "Asia/Tokyo", "order still follows the effective default"
    assert _selected(_tz_select(page)) == "UTC", "explicit URL wins selection"


def test_configured_default_wins_over_trusted_tz(web, monkeypatch):
    """An explicit configuration beats the regional TZ in order and Settings."""
    client, _ = web
    _login(client)
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
    page = client.get(f"/requests?site=default&{WINDOW_QS}").text
    values = _option_values(_tz_select(page))
    assert values[:2] == ["Europe/Berlin", "UTC"]
    assert _selected(_tz_select(page)) == "Europe/Berlin"
    settings = client.get("/settings").text
    assert ">Europe/Berlin</dd>" in settings

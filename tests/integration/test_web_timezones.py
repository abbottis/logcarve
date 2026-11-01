"""Dashboard display-timezone catalogue: completeness, order, defaults, overrides.

The hardcoded UTC/Berlin pair is replaced by the cached server-installed
IANA catalogue. These tests assert catalogue completeness against the
installed DB, stable option order, configured-default precedence,
explicit-override precedence, safe rejection of unknown/filesystem-style
zones, and real rendered times (tables + timeline) across representative
zones — including fractional offsets, DST and the Pacific. Synthetic data
only.
"""

import html
import json
import re
from urllib.parse import parse_qs, urlsplit
from zoneinfo import available_timezones

import pytest

from app.config import Settings
from app.web import timezones as tzmod

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"

ZONES_ALL_REGIONS = [
    "UTC",
    "Europe/Berlin",
    "America/New_York",
    "Asia/Tokyo",
    "Asia/Kathmandu",
    "Australia/Adelaide",
    "Pacific/Auckland",
]


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


def _params(url):
    return parse_qs(urlsplit(html.unescape(url)).query)


def _titles(page_html):
    return re.findall(r'<td class="tech" title="([^"]+)">', page_html)


def test_catalogue_is_complete_and_cached(web):
    client, _ = web
    _login(client)
    installed = available_timezones()
    assert len(installed) > 100, "installed DB must hold the full IANA set"
    assert tzmod._catalog() is tzmod._catalog(), "catalogue must be cached"
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    values = _option_values(_tz_select(page))
    assert set(values) == installed, "every supported key must be offered"
    assert len(values) == len(set(values)), "no duplicate option values"


def test_option_order_and_labels(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    values = _option_values(_tz_select(page))
    # Hermetic default is UTC, so UTC leads and the rest sort by region/zone.
    assert values[0] == "UTC"
    rest = values[1:]
    assert rest == sorted(
        rest, key=lambda n: (n.split("/")[0], n.split("/", 1)[1] if "/" in n else "")
    )
    regions = [v.split("/")[0] for v in rest]
    assert regions == sorted(regions), "regions must read alphabetically"
    labels = re.findall(r'<option value="[^"]+"[^>]*>([^<]+)</option>', _tz_select(page))
    assert len(labels) == len(values)
    assert all("_" not in label for label in labels), "labels must read with spaces"
    assert "America/Argentina/Buenos Aires" in labels, "multi-level zones keep readable labels"


def test_configured_default_first_and_applies(web, monkeypatch):
    client, _ = web
    _login(client)
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
    page = client.get(f"/?site=default&{WINDOW_QS}").text
    values = _option_values(_tz_select(page))
    assert values[:2] == ["Europe/Berlin", "UTC"], "configured default leads, UTC stays next"
    selected = re.search(r'<option value="([^"]+)" selected>', _tz_select(page))
    assert selected and selected.group(1) == "Europe/Berlin"
    assert "Time (Europe/Berlin)" in client.get(f"/requests?site=default&{WINDOW_QS}").text


def test_default_timezone_env_exact_key_wins_over_abbreviation(monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    assert tzmod.resolve_default_timezone(None) == "UTC"
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    assert tzmod.resolve_default_timezone(None) == "Asia/Tokyo"
    # A fixed offset is not a region and must never be guessed from.
    monkeypatch.setenv("TZ", "UTC+2")
    assert tzmod.resolve_default_timezone(None) == "UTC"


def test_explicit_override_wins_over_default(web, monkeypatch):
    client, _ = web
    _login(client)
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
    page = client.get(f"/requests?site=default&{WINDOW_QS}&tz=Asia%2FTokyo").text
    assert "Time (Asia/Tokyo)" in page
    selected = re.search(r'<option value="([^"]+)" selected>', _tz_select(page))
    assert selected and selected.group(1) == "Asia/Tokyo"


def test_unknown_and_filesystem_zones_rejected(web):
    client, _ = web
    _login(client)
    for bad in (
        "tz=Nope%2FZone",
        "tz=localtime",
        "tz=..%2F..%2Fetc%2Fpasswd",
        "tz=..\\windows",
    ):
        response = client.get(f"/?site=default&{WINDOW_QS}&{bad}")
        assert response.status_code == 400, bad
        assert "root:" not in response.text
    assert client.get(f"/requests?site=default&{WINDOW_QS}&tz=Nope%2FZone").status_code == 400
    partial = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=Nope%2FZone")
    assert partial.status_code == 400


def test_display_times_shift_but_instants_hold(web):
    client, _ = web
    _login(client)
    utc = client.get(f"/requests?site=default&{WINDOW_QS}&tz=UTC").text
    utc_titles = _titles(utc)
    assert utc_titles, "explorer rows must render"
    seen_labels = set()
    for zone in ZONES_ALL_REGIONS:
        page = client.get(f"/requests?site=default&{WINDOW_QS}&tz={zone.replace('/', '%2F')}").text
        assert f"Time ({zone})" in page
        assert _titles(page) == utc_titles, f"{zone}: UTC instants must stay identical"
        shown = re.findall(r'<td class="tech" title="[^"]+">([^<]+)</td>', page)
        seen_labels.add(tuple(shown))
    assert len(seen_labels) > 1, "displayed times must actually shift with the zone"


def test_timeline_labels_follow_zone(web):
    client, _ = web
    _login(client)
    utc = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    tokyo = client.get(f"/?site=default&{WINDOW_QS}&tz=Asia%2FTokyo").text
    nul = re.compile(
        r'<script id="traffic-timeline-data" type="application/json">(.*?)</script>', re.DOTALL
    )
    utc_labels = [
        b["label"] for b in json.loads(html.unescape(nul.search(utc).group(1)))["buckets"]
    ]
    tokyo_labels = [
        b["label"] for b in json.loads(html.unescape(nul.search(tokyo).group(1)))["buckets"]
    ]
    assert utc_labels and tokyo_labels != utc_labels


def test_fractional_zones_render_tables_but_truthful_heatmap(web):
    client, _ = web
    _login(client)
    for zone in ("Asia/Kathmandu", "Australia/Adelaide"):
        rows = client.get(f"/requests?site=default&{WINDOW_QS}&tz={zone.replace('/', '%2F')}").text
        assert f"Time ({zone})" in rows and _titles(rows), f"{zone} table must render"
        overview = client.get(f"/?site=default&{WINDOW_QS}&tz={zone.replace('/', '%2F')}").text
        assert "Heatmap unavailable for this timezone" in overview
        assert overview.count('data-heat-level="') == 0 or "heat-0" in overview
    for zone in ("America/New_York", "Pacific/Auckland", "Asia/Tokyo"):
        overview = client.get(f"/?site=default&{WINDOW_QS}&tz={zone.replace('/', '%2F')}").text
        assert overview.count('data-heat-level="') == 7 * 24, f"{zone} heatmap must render"
        assert "Heatmap unavailable" not in overview


def test_dst_zone_renders_both_sides(web):
    client, _ = web
    _login(client)
    summer = "range=custom&from=2026-07-27T00:00:00%2B00:00&to=2026-07-28T00:00:00%2B00:00"
    winter = "range=custom&from=2026-01-27T00:00:00%2B00:00&to=2026-01-28T00:00:00%2B00:00"
    for window in (summer, winter):
        response = client.get(f"/requests?site=default&{window}&tz=America%2FNew_York")
        assert response.status_code == 200
        selected = re.search(r'<option value="([^"]+)" selected>', _tz_select(response.text))
        assert selected and selected.group(1) == "America/New_York"


def test_nav_and_evidence_keep_explicit_zone(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=Asia%2FTokyo").text
    match = re.search(r'href="(/security\?[^"]+)"', page)
    assert match, "sidebar security link must render"
    assert _params(match.group(1)).get("tz") == ["Asia/Tokyo"]


def test_settings_default_timezone_validation(monkeypatch):
    from pydantic import ValidationError

    monkeypatch.setenv("DEFAULT_TIMEZONE", "Asia/Tokyo")
    assert Settings().default_timezone == "Asia/Tokyo"
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Nope/Zone")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.setenv("DEFAULT_TIMEZONE", "")
    with pytest.raises(ValidationError):
        Settings()

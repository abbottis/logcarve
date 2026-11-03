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


def _expected_catalogue(installed) -> set:
    """Installed keys minus non-portable filesystem specials.

    Mirrors the application filter: ``localtime``, ``posixrules`` and
    the ``posix/``/``right/`` implementation subtrees are never offered.
    """
    return {
        k
        for k in installed
        if k not in ("localtime", "posixrules")
        and not k.startswith("posix/")
        and not k.startswith("right/")
    }


def test_catalogue_is_complete_and_cached(web):
    client, _ = web
    _login(client)
    installed = available_timezones()
    assert len(installed) > 100, "installed DB must hold the full IANA set"
    assert tzmod._catalog() is tzmod._catalog(), "catalogue must be cached"
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    values = _option_values(_tz_select(page))
    expected = _expected_catalogue(installed)
    assert set(values) == expected, "every valid installed key must be offered"
    assert len(values) == len(set(values)), "no duplicate option values"
    for special in ("localtime", "posixrules"):
        assert special not in values, f"{special} must never be offered"
    assert not any(v.startswith(("posix/", "right/")) for v in values)


def test_catalogue_filtering_is_hermetic(monkeypatch):
    """Controlled catalogue proves special-entry filtering on every host.

    Uses a tiny deterministic dataset with the filesystem specials plus
    a real-looking alias, so filtering and alias retention hold even on
    hosts whose system database already hides ``localtime``.
    """
    controlled = {
        "UTC",
        "Europe/Berlin",
        "CET",
        "localtime",
        "posixrules",
        "posix/America/New_York",
        "right/Europe/Berlin",
    }
    from zoneinfo import ZoneInfoNotFoundError

    real_zone = tzmod.ZoneInfo

    def _fake_zone(name):
        if name in ("UTC", "Europe/Berlin", "CET"):
            return real_zone("UTC")
        raise ZoneInfoNotFoundError(name)

    monkeypatch.setattr(tzmod, "available_timezones", lambda: set(controlled))
    monkeypatch.setattr(tzmod, "ZoneInfo", _fake_zone)
    tzmod._catalog.cache_clear()
    tzmod._sorted_rest.cache_clear()
    try:
        keys = tzmod.catalog_keys()
        assert "CET" in keys, "genuine installed aliases are retained"
        assert "Europe/Berlin" in keys
        for special in (
            "localtime",
            "posixrules",
            "posix/America/New_York",
            "right/Europe/Berlin",
        ):
            assert special not in keys, f"{special} must be filtered"
        assert tzmod.resolve_request_timezone("localtime", None) is None
        assert tzmod.resolve_request_timezone(" CET ", None) == "CET"
    finally:
        tzmod._catalog.cache_clear()
        tzmod._sorted_rest.cache_clear()


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
    assert any(label.startswith("America/Argentina/Buenos Aires — UTC") for label in labels), (
        "multi-level zones keep readable labels with signed offsets"
    )


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
    # Installed abbreviations and fixed-offset Etc entries stay
    # explicitly selectable, but automatic TZ detection must never
    # guess them as a region. Alias availability legitimately differs
    # by OS/database, so each name is asserted against the installed
    # catalogue: present aliases stay offered, absent ones stay unoffered,
    # and TZ detection falls back to UTC in both cases.
    for abbrev in ("CET", "EST", "Etc/GMT+2"):
        if abbrev in tzmod.catalog_keys():
            monkeypatch.setenv("TZ", abbrev)
            assert tzmod.resolve_default_timezone(None) == "UTC", abbrev
        else:
            assert abbrev not in tzmod.catalog_keys(), f"{abbrev} absent stays unoffered"
            monkeypatch.setenv("TZ", abbrev)
            assert tzmod.resolve_default_timezone(None) == "UTC", abbrev
    # Path syntax is never accepted as a server region name.
    monkeypatch.setenv("TZ", "/usr/share/zoneinfo/Asia/Tokyo")
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


def test_settings_validator_never_enumerates_catalogue(monkeypatch):
    """Three Settings constructions must not enumerate the zone files.

    `load_settings` runs per request, so the validator proves a single
    key with one `ZoneInfo` construction instead of calling
    `available_timezones` on every `Settings` instance.
    """
    from zoneinfo import available_timezones as real_catalogue

    calls = []
    import app.config as config_mod

    monkeypatch.setenv("DEFAULT_TIMEZONE", "Asia/Tokyo")
    monkeypatch.setattr(
        config_mod,
        "available_timezones",
        lambda: calls.append(1) or real_catalogue(),
        raising=False,
    )
    for _ in range(3):
        assert Settings(_env_file=None).default_timezone == "Asia/Tokyo"
    assert calls == [], "validator must not enumerate the filesystem catalogue"


def test_absent_config_uses_trusted_tz_through_routing(web, monkeypatch):
    """Absent DEFAULT_TIMEZONE resolves the regional server TZ in routing.

    With no explicitly configured default, `TZ=Asia/Tokyo` reaches real
    pages through `Settings`/request routing (not only the standalone
    resolver helper); an explicit `DEFAULT_TIMEZONE` always wins.
    """
    client, _ = web
    _login(client)
    monkeypatch.delenv("DEFAULT_TIMEZONE", raising=False)
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    page = client.get(f"/requests?site=default&{WINDOW_QS}").text
    assert "Time (Asia/Tokyo)" in page
    monkeypatch.setenv("DEFAULT_TIMEZONE", "Europe/Berlin")
    page = client.get(f"/requests?site=default&{WINDOW_QS}").text
    assert "Time (Europe/Berlin)" in page


def test_explicit_abbreviation_zone_follows_installed_db(web):
    """Alias selectability follows the server-installed database.

    When CET ships with the installed tz database it stays an explicit
    tz option (HTTP 200); when the database omits it, CET is unoffered
    and safely rejected (HTTP 400). Either way the contract holds
    without assuming any platform ships the alias.
    """
    client, _ = web
    _login(client)
    if "CET" in tzmod.catalog_keys():
        response = client.get(f"/requests?site=default&{WINDOW_QS}&tz=CET")
        assert response.status_code == 200
        assert "Time (CET)" in response.text
    else:
        assert "CET" not in tzmod.catalog_keys()
        response = client.get(f"/requests?site=default&{WINDOW_QS}&tz=CET")
        assert response.status_code == 400


def test_partial_swap_carries_updated_timezone_notice(web):
    """A successful htmx Apply updates the displayed-timezone notice.

    The notice lives outside `#page-content`, so every data partial
    carries an out-of-band update with the server-validated zone; a
    failed Apply (400) carries none and the stale notice stays put.
    """
    client, _ = web
    _login(client)
    partial = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=Pacific%2FAuckland")
    assert partial.status_code == 200
    assert 'id="filter-times-notice"' in partial.text
    assert "hx-swap-oob" in partial.text
    assert "Times shown in Pacific/Auckland" in partial.text
    for fragment in (
        "crawlers",
        "errors",
        "requests",
        "security",
    ):
        response = client.get(f"/partials/{fragment}?site=default&{WINDOW_QS}&tz=Asia%2FTokyo")
        assert response.status_code == 200, fragment
        assert "Times shown in Asia/Tokyo" in response.text, fragment
    bad = client.get(f"/partials/overview?site=default&{WINDOW_QS}&tz=Nope%2FZone")
    assert bad.status_code == 400
    assert "filter-times-notice" not in bad.text


def test_missing_zone_db_fails_fast_deterministically(monkeypatch):
    """Absent zone data names UTC but cannot render without the DB.

    Rendering any zone (including UTC) requires the tz database; the
    fallback is a deterministic UTC name plus a safe 400, never silent
    UTC-looking output or a crash. Documents the tzdata prerequisite.
    """
    import app.web.timezones as tz_module

    monkeypatch.setattr(
        tz_module, "available_timezones", lambda: (_ for _ in ()).throw(OSError("no zone db"))
    )
    tz_module._catalog.cache_clear()
    tz_module._sorted_rest.cache_clear()
    try:
        assert tz_module._catalog() == ("UTC",)
        assert tz_module.resolve_default_timezone(None) == "UTC"
    finally:
        tz_module._catalog.cache_clear()
        tz_module._sorted_rest.cache_clear()


def test_missing_zone_db_request_fails_fast(web, monkeypatch):
    """A data page without a usable zone DB fails fast with a safe 400."""
    from zoneinfo import ZoneInfoNotFoundError

    import app.web.routes as routes_mod

    client, _ = web
    _login(client)
    monkeypatch.setattr(
        routes_mod, "ZoneInfo", lambda name: (_ for _ in ()).throw(ZoneInfoNotFoundError("no db"))
    )
    response = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC")
    assert response.status_code == 400

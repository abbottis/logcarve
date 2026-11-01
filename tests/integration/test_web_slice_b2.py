"""Slice B correction regressions: every accepted gap from the
independent B review (2026-11-01) gets a maintained assertion here.

Selected traffic/bot matchers survive sidebar navigation and Ask;
timelines carry errors/bytes; provider/purpose/category aggregates come
from the shared layer exact over the full scope; paths have visible
sorts plus bytes; the heatmap shades quantitatively; the explorer shows
bytes/referrer/rule with timezone-aware times; method/exact-status/
referrer are visible controls; search matches the 128-char contract.
Synthetic data only.
"""

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app.analytics import service
from app.analytics.contracts import AnalyticsFilter, BotTableQuery, TimeWindow
from app.analytics.rules import load_rules

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
ROOT = Path(__file__).resolve().parent.parent.parent


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def _params(url):
    return parse_qs(urlsplit(html.unescape(url)).query)


def _timeline_data(page_html):
    match = re.search(
        r'<script id="traffic-timeline-data" type="application/json">(.*?)</script>',
        page_html,
        re.DOTALL,
    )
    assert match, "timeline JSON must be embedded"
    return json.loads(html.unescape(match.group(1)))


def test_timeline_carries_errors_and_bytes(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    data = _timeline_data(page)
    assert data["errorsLabel"] == "Errors"
    assert data["bytesLabel"] == "Known bytes"
    for bucket in data["buckets"]:
        assert "errors" in bucket and "bytes_total" in bucket
    assert sum(b["requests"] for b in data["buckets"]) > 0
    # Table alternative carries the same three datasets.
    assert "Known bytes" in page


def test_paths_visible_sort_and_bytes_column(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    page = client.get(f"/?{base}").text
    assert 'aria-label="Sort paths"' in page
    assert "Bytes" in page
    assert 'aria-sort="descending">Requests' in page
    by_bytes = client.get(f"/?{base}&paths_sort=bytes_desc").text
    assert 'aria-sort="descending">Known bytes' in by_bytes or "Bytes</th>" in by_bytes
    assert client.get(f"/?{base}&paths_sort=bogus").status_code == 400
    assert client.get(f"/partials/overview?{base}&paths_sort=bogus").status_code == 400


def test_heatmap_shading_levels_and_legend(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    cells = re.findall(r'data-heat-level="(\d)"', page)
    assert len(cells) == 7 * 24, "every weekday/hour cell carries a level"
    assert all(level in "01234" for level in cells)
    assert "4" in cells, "the busiest cell must reach the top level"
    assert "Cell shading scales from no requests" in page
    for level in range(5):
        assert f'class="heat-swatch heat-{level}"' in page, "legend needs every swatch"


def test_explorer_columns_timezone_and_sanitization(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    page = client.get(f"/requests?{base}").text
    for header in ("Bytes", "Referring domain", "Rule", "Time (UTC)"):
        assert header in page
    # The seeded attack UA is truncated to 200 chars and escaped.
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    berlin = client.get(f"/requests?{base}".replace("tz=UTC", "tz=Europe%2FBerlin")).text
    assert "Time (Europe/Berlin)" in berlin
    utc_cells = re.findall(r'<td class="tech" title="([^"]+)">([^<]+)</td>', page)
    berlin_cells = re.findall(r'<td class="tech" title="([^"]+)">([^<]+)</td>', berlin)
    assert utc_cells and berlin_cells, "explorer rows must render"
    # UTC instants are identical; displayed times shift with the timezone.
    assert [title for title, _ in utc_cells] == [title for title, _ in berlin_cells]
    assert [shown for _, shown in utc_cells] != [shown for _, shown in berlin_cells]
    assert any("CET" in shown or "CEST" in shown for _, shown in berlin_cells)


def test_bot_groups_exact_and_pagination_independent(web):
    client, _ = web
    _login(client)
    base = f"site=default&{WINDOW_QS}&tz=UTC"
    page = client.get(f"/crawlers?{base}").text
    assert "Claimed bots by category, provider and purpose" in page
    assert "configured catalog claims" in page
    assert 'id="bot-provider-groups-data"' in page
    # Grouped shares ignore the table page limit/offset exactly.
    narrow = client.get(f"/crawlers?{base}&limit=1&offset=1").text
    assert narrow.count("bot-provider-groups-data") == 1
    full_groups = re.findall(r'class="tech break-all">([^<]+)</td>', page)
    narrow_groups = re.findall(r'class="tech break-all">([^<]+)</td>', narrow)
    assert full_groups and full_groups == narrow_groups


def test_bot_groups_service_matches_table_totals(web):
    client, db = web
    _login(client)
    from app.db.database import connect

    rules = load_rules(ROOT / "config" / "bot_rules.yaml").rules
    conn = connect(db, read_only=True)
    window = TimeWindow(
        time_from=datetime(2026, 10, 27, tzinfo=UTC),
        time_to=datetime(2026, 10, 28, tzinfo=UTC),
    )
    filt = AnalyticsFilter(site_id="default", window=window)
    try:
        table = service.bot_table(conn, BotTableQuery(filt=filt), rules)
        groups = service.bot_groups(conn, filt, rules)
    finally:
        conn.close()
    table_total = sum(item["requests"] for item in table["items"])
    assert table_total > 0, "fixture must contain claimed bots"
    assert sum(g["requests"] for g in groups["providers"]) == table_total
    assert sum(g["requests"] for g in groups["categories"]) == table_total
    assert sum(g["requests"] for g in groups["purposes"]) == table_total
    assert sum(g["bytes_total"] for g in groups["providers"]) == sum(
        item["bytes_total"] for item in table["items"]
    )


def test_filter_bar_visible_matchers_and_search_contract(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC&method=GET&status=200").text
    for control in ('name="method"', 'name="status"', 'name="referer_host"'):
        assert control in page, f"visible control missing: {control}"
    assert 'id="f-status"' in page and 'id="f-method"' in page
    assert 'id="f-referer-host"' in page
    assert 'name="search" type="search"' in page
    assert 'maxlength="128"' in page
    assert 'maxlength="200"' not in page, "search must match the 128-char contract"
    for name in ("method", "status", "referer_host"):
        assert page.count(f'name="{name}"') == 1, f"duplicate field: {name}"
    # Applied values round-trip through the visible controls.
    assert 'value="GET"' in page
    assert 'value="200"' in page


def test_ask_scope_carries_selected_matchers(web):
    client, _ = web
    _login(client)
    page = client.get(
        f"/ask?site=default&{WINDOW_QS}&tz=UTC&traffic=claimed_bot"
        "&bot=bot-auto-curl&method=GET&status=404&search=docs"
    ).text
    assert page.count("data-ask") >= 1
    for attr in (
        'data-traffic="claimed_bot"',
        'data-bot="bot-auto-curl"',
        'data-method="GET"',
        'data-status="404"',
        'data-search="docs"',
    ):
        assert attr in page, f"Ask scope must carry {attr}"


def test_settings_and_sources_keep_matchers_roundtrip(web):
    client, _ = web
    _login(client)
    scoped = f"/?site=default&{WINDOW_QS}&tz=UTC&traffic=claimed_bot&status=404"
    overview = client.get(scoped)
    assert overview.status_code == 200
    settings_hrefs = [
        m for m in re.findall(r'href="([^"]+)"', overview.text) if m.startswith("/settings")
    ]
    assert settings_hrefs, "side nav must link to Settings"
    assert _params(settings_hrefs[0])["traffic"] == ["claimed_bot"]
    assert _params(settings_hrefs[0])["status"] == ["404"]
    settings = client.get(html.unescape(settings_hrefs[0]))
    assert settings.status_code == 200
    back = [
        h for h in re.findall(r'href="([^"]+)"', settings.text) if h == "/" or h.startswith("/?")
    ]
    assert back, "Settings must link back with state"
    assert _params(back[0])["traffic"] == ["claimed_bot"]
    assert _params(back[0])["status"] == ["404"]
    again = client.get(html.unescape(back[0]))
    assert again.status_code == 200
    assert "Claimed bots" in again.text

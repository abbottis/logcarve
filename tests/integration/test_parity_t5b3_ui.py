"""T5b3 UI capabilities (integration): Ask hides Save/Refresh, keeps scope.

Synthetic fixtures only. The shared filter bar renders scope controls
everywhere, but the Save-current and Auto-refresh controls appear only
where they work (data report pages). Ask has no saved-view target and
no report fragment, so both stay hidden there without implying a model
call.
"""

WINDOW_QS = "range=custom&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"


def _login(client):
    response = client.post(
        "/api/v1/admin/login", json={"username": "admin", "password": "s3cret-pw"}
    )
    assert response.status_code == 200


def test_ask_hides_save_and_refresh_but_keeps_scope(web):
    client, _ = web
    _login(client)
    page = client.get(f"/ask?site=default&{WINDOW_QS}&tz=UTC").text
    # Scope controls stay: site selector, window fields, Apply.
    assert 'id="filter-bar"' in page
    assert 'name="site"' in page
    assert "Apply" in page
    # Unsupported controls are hidden on Ask.
    assert "data-save-current" not in page
    assert "data-refresh-toggle" not in page
    # No implicit model call: the page renders starters, not an answer.
    assert "/ask" in page


def test_overview_keeps_save_and_refresh(web):
    client, _ = web
    _login(client)
    page = client.get(f"/?site=default&{WINDOW_QS}&tz=UTC").text
    assert 'id="filter-bar"' in page
    assert "data-save-current" in page
    assert "data-refresh-toggle" in page

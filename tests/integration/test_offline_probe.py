"""Unit tests for the smoke offline probe's transport/query/auth isolation.

The helper itself executes inside Docker (coordinator-run), but its three
failure classes from the persistent-demo repro are pinned here without
sockets: query encoding (`+00:00` must not decode to spaces), Bearer opener
isolation (no cookie jar may mask the token-only verdict), and chat-body
schema validity (short bodies 400/422 and mask auth).
"""

import importlib.util
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "smoke_offline_probe", ROOT / "scripts" / "smoke_offline_probe.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_window_params_encode_plus_offsets():
    helper = _load_helper()
    params = helper._window_params()
    assert "+00:00" not in params, "raw + would decode to spaces server-side"
    assert "%2B00%3A00" in params
    parsed = urllib.parse.parse_qs(params)
    assert parsed["from"] == [helper.WINDOW_FROM]
    assert parsed["to"] == [helper.WINDOW_TO]
    assert parsed["site_id"] == ["default"]


def test_bearer_opener_carries_no_cookie_jar():
    helper = _load_helper()
    bearer = helper._bearer_opener()
    assert not any(
        isinstance(handler, urllib.request.HTTPCookieProcessor) for handler in bearer.handlers
    ), "a jar would attach session cookies and mask the token-only verdict"


def test_session_opener_is_cookie_isolated_from_bearer():
    helper = _load_helper()
    session_handlers = [
        handler
        for handler in helper._session_opener().handlers
        if isinstance(handler, urllib.request.HTTPCookieProcessor)
    ]
    assert len(session_handlers) == 1
    jars = {
        id(handler.cookiejar)
        for handler in helper._bearer_opener().handlers
        if isinstance(handler, urllib.request.HTTPCookieProcessor)
    }
    assert not jars, "bearer opener must not share any cookie jar"


def test_chat_body_is_schema_valid():
    helper = _load_helper()
    body = helper._chat_body()
    assert set(body) == {"question", "site_id", "time_from", "time_to"}
    assert body["question"] and body["site_id"]
    assert body["time_from"] < body["time_to"]

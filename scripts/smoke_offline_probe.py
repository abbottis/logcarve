#!/usr/bin/env python3
"""In-network offline probe for the T10 smoke stack (tracked helper).

Runs INSIDE the isolated Compose network as a one-off container
(`docker compose run ... python - < scripts/smoke_offline_probe.py`) because
Docker 29 does not publish host ports on `internal: true` networks: the host
cannot curl the smoke stack, so every HTTP check executes here against the
app service over the isolated network. Stdlib only, finite timeouts, no
retries, no proxy, no new dependency.

Inputs (environment only, never argv): SMOKE_BASE_URL (default
http://app:8080), LOGCARVE_ADMIN_PASSWORD, SMOKE_ADMIN_USER (default
smoke-admin), SMOKE_TOKEN_FILE (default /run/smoke/token.txt),
SMOKE_WINDOW_FROM/TO (default the 30-row fixture window).

Output: `PASS: ...` lines plus a final `OFFLINE_RESULT pass=N fail=M` line.
Exit 0 only when every check passes. Prints counts and statuses only —
never tokens, passwords, or cookies.
"""

import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_S = 10
WINDOW_FROM = os.environ.get("SMOKE_WINDOW_FROM", "2026-10-26T00:00:00+00:00")
WINDOW_TO = os.environ.get("SMOKE_WINDOW_TO", "2026-10-29T00:00:00+00:00")
CHAT_QUESTION = "What claimed AI crawler activity is visible?"


def _window_params() -> str:
    """URL-encoded window query: raw `+00:00` would decode to spaces."""
    return urllib.parse.urlencode({"site_id": "default", "from": WINDOW_FROM, "to": WINDOW_TO})


def _chat_body() -> dict:
    """Schema-valid chat body: short bodies 400/422 and mask the auth guard."""
    return {
        "question": CHAT_QUESTION,
        "site_id": "default",
        "time_from": WINDOW_FROM,
        "time_to": WINDOW_TO,
    }


def _session_opener():
    """Cookie-bearing opener for the login/session legs only."""
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )


def _bearer_opener():
    """Stateless opener for every Bearer request: no jar, so no session or
    missing-CSRF response can mask the token-only verdict."""
    return urllib.request.build_opener()


def _base() -> str:
    return os.environ.get("SMOKE_BASE_URL", "http://app:8080").rstrip("/")


def _request(opener, method, path, *, body=None, token=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(_base() + path, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=TIMEOUT_S) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def _wait_ready() -> int:
    """Poll /healthz until healthy (90 s budget); startup gate only."""
    import time

    opener = urllib.request.build_opener()
    deadline = time.monotonic() + 90
    while True:
        try:
            with opener.open(_base() + "/healthz", timeout=5) as response:
                doc = json.loads(response.read().decode("utf-8"))
                if response.status == 200 and doc.get("ai_enabled") is False:
                    print("PASS: stack healthy (ai_enabled=false)")
                    return 0
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            print("FAIL: stack did not become healthy in 90s")
            return 1
        time.sleep(2)


def main() -> int:
    if "--wait" in sys.argv[1:]:
        return _wait_ready()
    passed, failed = 0, 0

    def good(name):
        nonlocal passed
        passed += 1
        print(f"PASS: {name}")

    def bad(name, detail=""):
        nonlocal failed
        failed += 1
        print(f"FAIL: {name} {detail}".rstrip())

    opener = _session_opener()
    tokens = _bearer_opener()

    status, payload = _request(opener, "GET", "/healthz")
    try:
        doc = json.loads(payload)
        assert status == 200 and doc["status"] == "ok" and doc["ai_enabled"] is False
        good("public liveness, ai_enabled=false")
    except (AssertionError, ValueError, KeyError):
        bad("public liveness", f"HTTP {status}")

    status, _ = _request(opener, "GET", "/readyz")
    if status == 401:
        good("unauthenticated /readyz is 401 (gating proof)")
    else:
        bad("unauthenticated /readyz", f"want 401, got {status}")

    password = os.environ.get("LOGCARVE_ADMIN_PASSWORD", "")
    username = os.environ.get("SMOKE_ADMIN_USER", "smoke-admin")
    status, payload = _request(
        opener,
        "POST",
        "/api/v1/admin/login",
        body={"username": username, "password": password or "\0"},
    )
    logged_in = False
    try:
        assert status == 200 and json.loads(payload)["csrf_token"]
        logged_in = True
    except (AssertionError, ValueError, KeyError):
        bad("private admin login", f"HTTP {status}")
    if logged_in:
        status, payload = _request(opener, "GET", "/readyz")
        try:
            assert status == 200 and json.loads(payload).get("ready") is True
            good("private admin readyz")
        except (AssertionError, ValueError):
            bad("private admin readyz", f"HTTP {status}")

    token_path = os.environ.get("SMOKE_TOKEN_FILE", "/run/smoke/token.txt")
    try:
        with open(token_path, encoding="utf-8") as handle:
            token = handle.read().strip()
        assert token
    except (OSError, AssertionError):
        token = ""
        bad("scoped token file readable", token_path)
    if token:
        # Browser `site` is `site_id` on the HTTP contract.
        params = _window_params()
        summary_status, summary_payload = _request(
            tokens, "GET", f"/api/v1/summary?{params}", token=token
        )
        try:
            assert summary_status == 200
            assert json.loads(summary_payload)["totals"]["requests"] == 30
            good("scoped client summary, 30 requests, no model key")
        except (AssertionError, ValueError, KeyError):
            bad("scoped client summary", f"HTTP {summary_status}")
        for endpoint in ("crawlers", "security/findings"):
            status, _ = _request(tokens, "GET", f"/api/v1/{endpoint}?{params}", token=token)
            if status == 200:
                good(f"scoped client {endpoint}")
            else:
                bad(f"scoped client {endpoint}", f"HTTP {status}")
        status, _ = _request(tokens, "POST", "/api/v1/chat/ask", body=_chat_body(), token=token)
        if status == 401:
            good("Bearer token cannot reach chat (no model proxy)")
        else:
            bad("Bearer token chat guard", f"want 401, got {status} (short body would mask auth)")

    print(f"OFFLINE_RESULT pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

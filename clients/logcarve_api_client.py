#!/usr/bin/env python3
"""Reproducible external LogCarve analytics client (T5).

Calls the versioned read-only API over plain HTTPS/HTTP with a scoped
Bearer [REDACTED] taken from ``LOGCARVE_API_TOKEN`` or ``--token``. Standard
library only: no third-party dependencies, no model access, no imports.
Prints one JSON document per endpoint.

Example:
    LOGCARVE_API_TOKEN=lc_... python clients/logcarve_api_client.py \\
        --base-url http://127.0.0.1:8080 --site default \\
        --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ENDPOINTS = ("summary", "crawlers", "findings")
TIMEOUT_S = 30


def _token(args: argparse.Namespace) -> str:
    token = args.token or os.environ.get("LOGCARVE_API_TOKEN", "")
    if not token:
        print("error: provide --token or LOGCARVE_API_TOKEN", file=sys.stderr)
        raise SystemExit(2)
    return token


def fetch(base_url: str, token: str, endpoint: str, params: dict[str, str]) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    route = "security/findings" if endpoint == "findings" else endpoint
    url = f"{base_url.rstrip('/')}/api/v1/{route}?{query}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except OSError:
            detail = ""
        print(f"error: HTTP {exc.code} for {endpoint}: {detail[:500]}", file=sys.stderr)
        raise SystemExit(1)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"error: request failed for {endpoint}: {exc}", file=sys.stderr)
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="External LogCarve analytics client")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--site", required=True)
    parser.add_argument("--from", dest="time_from", required=True)
    parser.add_argument("--to", dest="time_to", required=True)
    parser.add_argument("--endpoint", choices=[*ENDPOINTS, "all"], default="all")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = _token(args)
    params = {"site_id": args.site, "from": args.time_from, "to": args.time_to}
    wanted = ENDPOINTS if args.endpoint == "all" else (args.endpoint,)
    documents = {name: fetch(args.base_url, token, name, params) for name in wanted}
    output = documents if len(documents) > 1 else documents[wanted[0]]
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

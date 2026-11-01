#!/usr/bin/env python3
"""Reproducible external LogCarve analytics client (T5).

Calls the versioned read-only API over plain HTTPS/HTTP with a scoped
Bearer token taken from ``LOGCARVE_API_TOKEN`` or ``--token``. Standard
library only: no third-party dependencies, no model access, no imports.
Prints one JSON document per endpoint; ``--endpoint`` also selects
typed report operations (``performance``, ``slow-endpoints``,
``seo-bot-statuses``, ``journeys``, ``comparison``, ...) and the
bounded streaming full-export downloads ``export-csv``/``export-json``
(which need ``--out`` and verify the body against the response
metadata instead of trusting a truncated file).

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
#: Typed report operations over the versioned read-only API. Each name
#: maps to one deterministic route; the model-assistant ``report``
#: enum is a subset of these aggregates (timelines, raw rows and the
#: streaming export stay outside the tool surface).
REPORT_ENDPOINTS = {
    "performance": "performance",
    "performance-overview": "performance/overview",
    "slow-endpoints": "performance/slow-endpoints",
    "seo-bot-statuses": "seo/bot-statuses",
    "seo-ai-only-paths": "seo/ai-only-paths",
    "referrer-404-targets": "referrers/404-targets",
    "journeys": "journeys",
    "journey-entries": "journeys/entry-paths",
    "comparison": "comparison",
    "traffic-breakdown": "traffic/breakdown",
    "resources": "traffic/resources",
    "browsers": "traffic/browsers",
    "heatmap": "traffic/heatmap",
}
EXPORT_FORMATS = ("export-csv", "export-json")
TIMEOUT_S = 30
#: Bounded streaming download: refuse to buffer more than this on disk
#: so a hostile scope cannot fill the filesystem silently. The server
#: row cap (250k rows) bounds legitimate exports well below this.
EXPORT_MAX_BYTES = 512 * 1024 * 1024
EXPORT_SCHEMA_VERSION = "export/1"


def _token(args: argparse.Namespace) -> str:
    token = args.token or os.environ.get("LOGCARVE_API_TOKEN", "")
    if not token:
        print("error: provide --token or LOGCARVE_API_TOKEN", file=sys.stderr)
        raise SystemExit(2)
    return token


def _route_for(endpoint: str) -> str:
    if endpoint == "findings":
        return "security/findings"
    return REPORT_ENDPOINTS.get(endpoint, endpoint)


def fetch(base_url: str, token: str, endpoint: str, params: dict[str, str]) -> dict:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base_url.rstrip('/')}/api/v1/{_route_for(endpoint)}?{query}"
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


def download_export(
    base_url: str,
    token: str,
    params: dict[str, str],
    export_format: str,
    dest: str,
    *,
    max_bytes: int = EXPORT_MAX_BYTES,
) -> dict:
    """Stream a full-result export to disk with completeness checks.

    The body streams in chunks (never buffered whole in memory) up to
    ``max_bytes``. Response metadata travels in headers only and is
    validated, never trusted blindly: the schema version must match,
    and the received body must be complete — a JSON envelope must
    parse with ``"complete": true`` and its row count must equal the
    header count, while a CSV body must carry the header row plus
    exactly the header row count. An incomplete or over-cap body
    removes the partial file and exits nonzero with a safe message
    (no token, no log content).
    """
    ext = "csv" if export_format == "export-csv" else "json"
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base_url.rstrip('/')}/api/v1/exports/requests?{query}&export_format={ext}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            headers = response.headers
            schema = headers.get("X-Logcarve-Export-Schema", "")
            expected_rows = headers.get("X-Logcarve-Export-Rows", "")
            if schema != EXPORT_SCHEMA_VERSION:
                print(
                    f"error: unexpected export schema {schema!r}; refusing download",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            try:
                expected = int(expected_rows)
            except ValueError:
                print(
                    "error: export row-count header is missing or invalid; refusing download",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            received = 0
            with open(dest, "wb") as handle:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > max_bytes:
                        handle.close()
                        _remove_partial(dest)
                        print(
                            "error: export exceeded the local size bound; partial file removed",
                            file=sys.stderr,
                        )
                        raise SystemExit(1)
                    handle.write(chunk)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except OSError:
            detail = ""
        print(f"error: HTTP {exc.code} for export: {detail[:500]}", file=sys.stderr)
        raise SystemExit(1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"error: request failed for export: {exc}", file=sys.stderr)
        raise SystemExit(1)
    return _verify_export_file(dest, ext, expected)


def _remove_partial(dest: str) -> None:
    try:
        os.remove(dest)
    except OSError:
        pass


def _verify_export_file(dest: str, ext: str, expected: int) -> dict:
    """Check a downloaded export for completeness; fail loudly if short."""
    try:
        with open(dest, "rb") as handle:
            blob = handle.read()
    except OSError as exc:
        print(f"error: cannot read downloaded export: {exc}", file=sys.stderr)
        raise SystemExit(1)
    if ext == "json":
        try:
            envelope = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _remove_partial(dest)
            print(
                "error: export body is truncated (not valid JSON); partial file removed",
                file=sys.stderr,
            )
            raise SystemExit(1)
        rows = envelope.get("rows")
        if envelope.get("complete") is not True or not isinstance(rows, list):
            _remove_partial(dest)
            print(
                "error: export body is incomplete (missing complete marker); partial file removed",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if len(rows) != expected or envelope.get("metadata", {}).get("row_count") != expected:
            _remove_partial(dest)
            print(
                f"error: export body holds {len(rows)} rows, expected {expected};"
                " partial file removed",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return {"path": dest, "format": "json", "rows": len(rows), "complete": True}
    text = blob.decode("utf-8", errors="replace")
    lines = text.splitlines()
    # Header row plus exactly the advertised record rows: a truncated
    # chunked body can never masquerade as a complete file.
    if len(lines) != expected + 1:
        _remove_partial(dest)
        print(
            f"error: export body holds {max(0, len(lines) - 1)} rows, expected {expected};"
            " partial file removed",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return {"path": dest, "format": "csv", "rows": expected, "complete": True}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="External LogCarve analytics client")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--site", required=True)
    parser.add_argument("--from", dest="time_from", required=True)
    parser.add_argument("--to", dest="time_to", required=True)
    parser.add_argument(
        "--endpoint",
        choices=[*ENDPOINTS, *REPORT_ENDPOINTS, *EXPORT_FORMATS, "all"],
        default="all",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Destination file for export-csv/export-json downloads.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = _token(args)
    params = {"site_id": args.site, "from": args.time_from, "to": args.time_to}
    if args.endpoint in EXPORT_FORMATS:
        if not args.out:
            print("error: provide --out for export downloads", file=sys.stderr)
            raise SystemExit(2)
        summary = download_export(args.base_url, token, params, args.endpoint, args.out)
        json.dump(summary, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if args.endpoint == "all":
        wanted = (*ENDPOINTS, *REPORT_ENDPOINTS)
    else:
        wanted = (args.endpoint,)
    documents = {name: fetch(args.base_url, token, name, params) for name in wanted}
    output = documents if len(documents) > 1 else documents[wanted[0]]
    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# External Agent & Workflow API

Core analytics endpoints are implemented (see Verified usage); the
full-result export below is implemented as the T3a slice (PAR-07).
Remaining planned surfaces stay planned until built. This API is an
independent MVP product capability, backed by the same deterministic
analytics as the dashboard and internal assistant.

## Planned endpoints

| Method/path | Data |
| --- | --- |
| `GET /api/v1/summary` | Request totals, error/bot shares and coverage |
| `GET /api/v1/traffic/timeseries` | Bounded request/status/byte time buckets |
| `GET /api/v1/traffic/breakdown` | Exact per-traffic-class totals (zero-filled) |
| `GET /api/v1/traffic/resources` | Requests/errors/bytes by path-based resource kind |
| `GET /api/v1/traffic/browsers` | Claimed browser family/OS shares (browser-like rows) |
| `GET /api/v1/traffic/heatmap` | Weekday/hour matrix for a display timezone (`tz`) |
| `GET /api/v1/traffic/clients` | Top pseudonymized clients, aggregates only |
| `GET /api/v1/crawlers` | Claimed crawler families, counts, paths and statuses |
| `GET /api/v1/bots` | Named-bot table with allowlisted sort and paging |
| `GET /api/v1/bots/{rule_id}` | One named bot: totals, top paths/404s, robots/sitemap, samples |
| `GET /api/v1/requests` | Sanitized paginated request explorer (allowlisted sorts incl. legacy `newest`/`oldest` plus `time/client/method/path/status/bytes` ascending/descending with timestamp/id tie-breaks and NULL-bytes-last, bounded `search`); rows carry the 200-char agent sample with an explicit `ua_truncated` flag and a derived `conflict` boolean for the conflicting-bot-identity candidate |
| `GET /api/v1/errors` | Error groups by path/status/referrer |
| `GET /api/v1/security/findings` | Deterministic investigation candidates with rule/evidence refs |
| `GET /api/v1/paths` | Top paths/methods/counts/errors/bytes |
| `GET /api/v1/referrers` | Referring domains and destination paths |
| `GET /api/v1/performance` | Measured duration distribution, or `available: false` |

All analytics endpoints accept the shared selectors `traffic`, `bot`,
`category`, `provider`, `purpose`, `search` (bounded, LIKE-escaped over the
stored path, user agent, referrer host and client pseudonym),
`status_class`, plus the existing method/status/path/referrer matchers and
`limit`/`offset` paging. Unknown or contradictory selectors reject with a
safe structured error; token site/source enforcement is unchanged.
| `GET /healthz` | Minimal liveness |
| `GET /readyz` | Restricted/internal DB readiness |

`POST /api/v1/chat/ask` is a separately authorized model operation; it is not part of the analytics-read contract. Admin imports are also separate. There is no raw-log export or general model-relay endpoint.

## Required request/response behavior

Authenticate via `Authorization: Bearer <token>` with `analytics:read` and authorized site. Enforce `site_id`, `from`, `to`, timezone, maximum window, bounded pagination/limit and stable sort on the server. Document exact defaults/field types in OpenAPI when implementing; no generated OpenAPI file exists yet.

Responses carry `site_id`, `time_range`, `generated_at`, `source_coverage`, `sample_size`, `filters`, `data_quality` and `warnings`. Findings include rule/evidence references. Use structured `code`, `message`, `request_id` errors without internal paths/SQL/secrets. Tokens are not URL parameters or browser JS settings.

## Integration examples

- curl/HTTP client: take the Bearer token from a protected environment or secret store, query summary/crawlers/findings and validate the JSON contract.
- n8n: HTTP Request with a credential-backed Authorization header, explicit site/time/limit and downstream processing of minimized JSON only.
- Agent tool: validate arguments and call only these approved analytics GET routes; do not grant database/filesystem access.

For public remote access require TLS; otherwise use local/private/VPN access. Server-side workflows do not require permissive CORS. Clients remain responsible for onward LLM transfers and privacy decisions.

### curl

```bash
export LOGCARVE_API_TOKEN="lc_..."  # scoped analytics:read token, shown once at issuance
BASE="http://127.0.0.1:8080"
curl -s -H "Authorization: Bearer $LOGCARVE_API_TOKEN" \
  "$BASE/api/v1/summary?site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
curl -s -H "Authorization: Bearer $LOGCARVE_API_TOKEN" \
  "$BASE/api/v1/security/findings?site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
curl -s -H "Authorization: Bearer $LOGCARVE_API_TOKEN" \
  "$BASE/api/v1/performance/slow-endpoints?site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
```

### Python client

`clients/logcarve_api_client.py` (stdlib only) performs the same calls and prints JSON:

```bash
LOGCARVE_API_TOKEN="lc_..." python clients/logcarve_api_client.py \
  --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00
LOGCARVE_API_TOKEN="lc_..." python clients/logcarve_api_client.py \
  --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00 \
  --endpoint slow-endpoints
```

### n8n sketch

HTTP Request node: GET `{{$json.baseUrl}}/api/v1/summary`, query parameters `site_id`, `from`, `to` (ISO UTC), header `Authorization: Bearer {{$credentials.logcarveApi.token}}` from a credential store (never a URL parameter). Follow with IF/Code nodes operating on the minimized JSON only.

## Full-result export (implemented, T3a / PAR-07)

Two download entries share one deterministic contract over the
allowlisted export columns (sanitized explorer projection plus
approved SAFE enrichment — stable HMAC pseudonyms; never original
client IPs, raw log lines, query values, keys, exception text or
stored diagnostics, even when an admin display mode is full):

- `GET /api/v1/exports/requests` — Bearer `analytics:read` (token
  site/source/time bounds apply exactly as on every analytics read).
- `GET /export/requests` — admin session cookie (browser download;
  Bearer [REDACTED] are never accepted here, no credential is read from the
  query string). No export UI is added yet.

Query: `site_id`, `from`/`to` (UTC ISO), optional `source_id` and
every shared selector, `timezone` (API: UTC only, else
`unsupported_timezone`; browser: any validated zone, recorded as
the display zone), `export_format` (`csv` default, or `json`) and
`sort` (allowlisted explorer order, default `oldest`).

Scope and streaming (documented, never silent truncation):

- The export always covers the ENTIRE filtered result: no
  `limit`/`offset` is accepted and none leaks into metadata or rows.
- Scopes above 250000 rows reject BEFORE streaming with HTTP 413
  `export_too_large` (narrow the window or filters instead).
- Rows stream from ONE owned read snapshot (count, cap, metadata,
  cursor and rows share a generation, so a concurrent append or
  retention pass can neither inflate rows past the cap nor split
  metadata from rows) in bounded 1000-row chunks — never
  `fetchall`, never page-size slicing. A failed stream never reads
  complete: JSON closes with `"complete": true` only on success; a
  CSV abort truncates mid-body.
- Needs no model client, key or network: works with chat disabled,
  no key and no Internet.

CSV transport (standard interoperability): the body is plain CSV —
one header row naming the export columns (CRLF, minimal quoting,
newline escaping by the CSV writer) plus one record per row; every
reproducibility field travels in ASCII-safe `X-Logcarve-Export-*`
headers (no preamble lines in the body):

| Header | Content |
| --- | --- |
| `X-Logcarve-Export-Schema` | `export/1` |
| `X-Logcarve-Export-Rows` | Exact row count (equals the streamed records) |
| `X-Logcarve-Export-Site` / `-Source` | Validated site (source empty when unfiltered) |
| `X-Logcarve-Export-Window` | UTC `time_from/time_to` pair |
| `X-Logcarve-Export-Timezone` | Selected display timezone (rows stay UTC) |
| `X-Logcarve-Export-Sort` | Selected row order |
| `X-Logcarve-Export-Generated-At` | Generation instant |
| `X-Logcarve-Export-Filters` | Compact JSON of the non-default validated filters (bounded by the contract maxima; defaults omitted) |
| `X-Logcarve-Export-Coverage` | Compact JSON: unique events, observed min/max, sources, line totals, import count plus per-import `id`/`status` capped at 50 with an explicit `imports_truncated` flag (never silent, never `error_summary`) |
| `X-Logcarve-Privacy` | Pseudonymization label |

JSON transport: `{"metadata": {...}, "rows": [...], "complete": true}`
with the same reproducibility set (`schema_version`, `site_id`,
`source_id`, UTC `time_range`, `display_timezone`, `sort`,
`generated_at`, full validated `filters`, exact `row_count`,
`coverage`, `data_quality` with line totals plus per-import
`id`/`status`, `privacy`, `limitations`).

Spreadsheet safety: string cells whose first meaningful character
(after Unicode whitespace, control and format bytes such as NUL,
NBSP, BOM or zero-width space) is `=`, `+`, `-` or `@` gain a
neutralizing single-quote prefix; the original text is preserved
verbatim behind it. `None` maps to empty, booleans to
`true`/`false`, meaningful numerics stay unquoted numbers. No
spreadsheet is launched and no formula is evaluated.

### curl

```bash
export LOGCARVE_API_TOKEN="lc_..."  # scoped analytics:read token, shown once at issuance
BASE="http://127.0.0.1:8080"
Q="site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
curl -s -D - -H "Authorization: Bearer $LOGCARVE_API_TOKEN" \
  "$BASE/api/v1/exports/requests?$Q&export_format=csv&sort=oldest" -o export.csv
curl -s -H "Authorization: Bearer $LOGCARVE_API_TOKEN" \
  "$BASE/api/v1/exports/requests?$Q&export_format=json&sort=newest" | python3 -c \
  "import json,sys; e=json.load(sys.stdin); print(e['metadata']['row_count'], e['complete'])"
```

Clients parse CSV with any standard CSV reader (header row first)
and read reproducibility metadata from the response headers; JSON
clients read the `metadata` envelope.

Response lifecycle (T3a fix): the streaming response releases its
owned read snapshot in an unconditional ASGI-call `finally` —
normal completion, renderer error, task cancellation, older-protocol
disconnect and a send failure before the first body byte all close
the cursor and snapshot exactly once, without relying on the row
generator or the background task. A caller that prepares an export
but never sends it closes the prepared handle explicitly instead of
dropping it.

### Stdlib client streaming download (T3b)

`clients/logcarve_api_client.py` (stdlib only, token from
`LOGCARVE_API_TOKEN` or `--token`, never from a URL) streams the
download to `--out` in bounded chunks and verifies it against the
response metadata instead of trusting a truncated file: the schema
header must read `export/1`, the row-count header must parse, JSON
must decode with `"complete": true` and a matching row count, and
CSV must hold the header row plus exactly the advertised records.
Any incomplete or over-cap body removes the partial file and exits
nonzero with a safe message (no token, no log content):

```bash
LOGCARVE_API_TOKEN="lc_..." python clients/logcarve_api_client.py \
  --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00 \
  --endpoint export-json --out /tmp/export.json
```

### n8n sketch (export)

HTTP Request node: GET `{{$json.baseUrl}}/api/v1/exports/requests`
with query `site_id`, `from`, `to`, `export_format=json` and header
`Authorization: Bearer {{$credentials.logcarveApi.token}}`. Follow
with an IF node asserting the `X-Logcarve-Export-Rows` header is
present and the parsed body has `"complete": true` with a matching
row count; treat any mismatch as a failed (never complete) download.

## Report operations (T3b)

The deterministic read-only report routes behind the assistant's
bounded `get_report` tool (aggregates only; timelines, raw rows and
the streaming export stay outside the tool surface) are available to
external callers with the same scoped token contract:

- `/api/v1/performance`, `/api/v1/performance/overview`, `/api/v1/performance/slow-endpoints`
- `/api/v1/seo/bot-statuses`, `/api/v1/seo/ai-only-paths`, `/api/v1/referrers/404-targets`, `/api/v1/referrers/urls`
- `/api/v1/journeys`, `/api/v1/journeys/entry-paths`, `/api/v1/comparison`
- `/api/v1/traffic/breakdown`, `/api/v1/traffic/resources`, `/api/v1/traffic/browsers`, `/api/v1/traffic/heatmap`

The stdlib client exposes each as a typed `--endpoint` operation
(`--endpoint slow-endpoints`, `--endpoint comparison`, ...) in
addition to `summary`/`crawlers`/`findings`, and the two download
operations (`--endpoint export-csv|export-json --out PATH`) with the
completeness checks above. The internal assistant additionally
enforces the trusted chat scope on every report (selected parent
matchers cannot be widened by model arguments; `false`/`0` are real
selections; comparison always reads the server-derived previous
window), holds one read snapshot per tool read released before any
provider dispatch, and projects bounded evidence with measured
timing carried as available/count (never a hardcoded unavailable
answer when enriched timing exists).

## Verified usage (T5)

Implemented routes: `/api/v1/summary`, `/api/v1/traffic/timeseries`, `/api/v1/crawlers`, `/api/v1/errors`, `/api/v1/paths`, `/api/v1/referrers`, `/api/v1/security/findings`, `/api/v1/performance`, plus protected `/api/v1/openapi.json`, restricted `/readyz` and public `/healthz`. Interactive docs are disabled. Timezone other than UTC is rejected (`unsupported_timezone`); windows over 366 days are rejected. Verified with chat disabled and no model key: pytest integration suite (TestClient) and the stdlib client against real loopback HTTP, comparing every analytic response with the shared service layer. Provider-failure checks repeat after T7, where model integration exists.

## Mandatory independent test

Disable chat, remove the product model key and deny/fail provider transport. With a valid scoped token, retrieve summary, crawlers and findings and compare them with common analytics results. Reject invalid/revoked/missing-scope/cross-site tokens, mutation attempts and hidden raw-log/model-proxy access. Record API-01–04 evidence.

Product MCP and signed webhooks are P1 and must wrap this authorized contract if later implemented. Development MCP connections do not implement this API.

# External Agent & Workflow API

**Planned contract; endpoints are not implemented.** This API is an independent MVP product capability, backed by the same deterministic analytics as the dashboard and internal assistant.

## Planned endpoints

| Method/path | Data |
| --- | --- |
| `GET /api/v1/summary` | Request totals, error/bot shares and coverage |
| `GET /api/v1/traffic/timeseries` | Bounded request/status time buckets |
| `GET /api/v1/crawlers` | Claimed crawler families, counts, paths and statuses |
| `GET /api/v1/errors` | Error groups by path/status/referrer |
| `GET /api/v1/security/findings` | Deterministic investigation candidates with rule/evidence refs |
| `GET /api/v1/paths` | Top paths/methods/counts/status groups |
| `GET /api/v1/referrers` | Referring domains and destination paths |
| `GET /api/v1/performance` | Measured duration distribution, or `available: false` |
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
curl -s -H "Authorization: Bearer $LOG[PAD]CARVE_API_TOKEN" \
  "$BASE/api/v1/summary?site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
curl -s -H "Authorization: Bearer $LOG[PAD]CARVE_API_TOKEN" \
  "$BASE/api/v1/security/findings?site_id=default&from=2026-10-27T00:00:00%2B00:00&to=2026-10-28T00:00:00%2B00:00"
```

### Python client

`clients/logcarve_api_client.py` (stdlib only) performs the same calls and prints JSON:

```bash
LOG[PAD]CARVE_API_TOKEN="lc_..." python clients/logcarve_api_client.py \
  --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-27T00:00:00+00:00 --to 2026-10-28T00:00:00+00:00
```

### n8n sketch

HTTP Request node: GET `{{$json.baseUrl}}/api/v1/summary`, query parameters `site_id`, `from`, `to` (ISO UTC), header `Authorization: Bearer {{$credentials.logcarveApi.token}}` from a credential store (never a URL parameter). Follow with IF/Code nodes operating on the minimized JSON only.

## Verified usage (T5)

Implemented routes: `/api/v1/summary`, `/api/v1/traffic/timeseries`, `/api/v1/crawlers`, `/api/v1/errors`, `/api/v1/paths`, `/api/v1/referrers`, `/api/v1/security/findings`, `/api/v1/performance`, plus protected `/api/v1/openapi.json`, restricted `/readyz` and public `/healthz`. Interactive docs are disabled. Timezone other than UTC is rejected (`unsupported_timezone`); windows over 366 days are rejected. Verified with chat disabled and no model key: pytest integration suite (TestClient) and the stdlib client against real loopback HTTP, comparing every analytic response with the shared service layer. Provider-failure checks repeat after T7, where model integration exists.

## Mandatory independent test

Disable chat, remove the product model key and deny/fail provider transport. With a valid scoped token, retrieve summary, crawlers and findings and compare them with common analytics results. Reject invalid/revoked/missing-scope/cross-site tokens, mutation attempts and hidden raw-log/model-proxy access. Record API-01–04 evidence.

Product MCP and signed webhooks are P1 and must wrap this authorized contract if later implemented. Development MCP connections do not implement this API.

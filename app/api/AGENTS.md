# API rules

Read the root rules, `docs/external-api.md` and API criteria in `docs/acceptance-criteria.md`.

- Keep transport validation in FastAPI/Pydantic; obtain metrics from `app/analytics/`.
- Version analytics endpoints under `/api/v1` and maintain an explicit OpenAPI response contract.
- Require Bearer token scope `analytics:read` and enforce the authorized site on every analytics request.
- Browser sessions are not substitutes for external API tokens; analytics tokens never authorize admin import.
- Validate time range, timezone, maximum window, pagination and limits; use stable tie-break sorting.
- Do not return raw logs, original client IPs, query values, credentials or internal ORM objects.
- Include site, time range, generation time, filters, sample size, coverage, quality and warnings.
- Findings include deterministic rule/evidence references; unavailable performance explicitly reports `available: false`.
- Keep health responses minimal; restrict readiness and sensitive API documentation appropriately.
- Admin import and `POST /api/v1/chat/ask` have separate authorization and rate limits.
- An analytics request must not create a model client, depend on chat or require any model key.
- Map failures to safe structured `code`, `message`, `request_id` responses without SQL or paths.
- Test invalid/expired/revoked tokens, missing scope, cross-site access, malformed filters and bounded results.
- Prove summary/crawlers/findings work with chat disabled and provider access unavailable.

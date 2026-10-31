# MVP scope

Status: derived from technical spec v0.4 on 2026-10-28; no product behavior implemented.

## Scope contract

Build a private, self-hosted Linux application for **one site and one configured NCSA Combined access-log source**, with tested Nginx and Apache samples. Import historical files in batches through a read-only local source. Normalize/persist in SQLite and present deterministic metrics through a local-assets browser dashboard.

Both integration paths are required:

1. A built-in server-side Meta assistant uses typed, bounded analytics tools and returns cited evidence.
2. External agents/workflows query a scoped Bearer-token REST API independently of chat, the model key and provider availability.

English UI/documentation, central i18n catalog, UTC storage, explicit display timezone, admin login, light/dark themes, privacy defaults, reproducible tests and Docker Compose are part of the target MVP.

## Ordered implementation slices

| Slice | Outcome | Acceptance IDs |
| --- | --- | --- |
| S0 — settle the plan | Architecture, auth, licensing/provenance and safe account setup decisions recorded | GOV-01, GOV-02 |
| S1 — ingest and store | Synthetic Nginx/Apache Combined → normalized SQLite with import accounting and safe source resolution | ING-01–05, DB-01–02 |
| S2 — deterministic API | Shared queries, token/scope/site enforcement, bounded JSON and external client with chat off | ANA-01–03, AUTH-01–02, API-01–04 |
| S3 — internal assistant | Verified Meta Standard adapter, sanitized tools/evidence, fake-provider tests and authorized real smoke call | AI-01–04, PRIV-01–03, COST-01–02 |
| S4 — dashboard | Login, Overview/Security/Crawlers/Errors/Ask AI/Settings and data sources with local assets | UI-01–04 |
| S5 — reproducible delivery | Fresh Linux Compose install, persistence/restore, benchmarks, independent review, documentation and demo | OPS-01–03, QA-01–02, GOV-03 |

Auth/privacy work belongs in each affected slice. S1 may be verified through a local CLI before browser import administration exists. S2 must not wait for a working LLM. Review critical boundaries before release.

## Required analysis paths

- Security: statuses, sensitive-path patterns and suspicious rates, with rule IDs and cautious investigation wording.
- Crawlers/SEO: declared families, paths/statuses and crawler 404s; claims remain unverified.
- Development: request volumes, endpoints, bytes and errors; latency only with actual timing data.
- Referrers: source domains and broken inbound paths, without session/conversion attribution.
- Three AI demonstrations: AI-crawler activity, 404s with referrers and suspicious request patterns.

## Later scope

P1: gzip/custom timing formats, incremental import/rotation, LiteSpeed fixtures, optional verified bots, exports, local chat history/streaming, product MCP server and signed event webhooks. Saved orchestration scripts/hooks also wait for a stable manual development procedure.

P2: multi-site/roles, continuous multi-source ingestion, error/CDN/WAF formats, correlation and larger storage systems when measured need justifies them. No automatic firewall/server mutation in the MVP.

## Before implementation

Resolve proposed choices through `/plan` and `/grill`; see `decisions/README.md`. Scaffold approval is not approval of those choices. Record accepted scope, affected files, acceptance IDs and the smallest testable next slice. Do not mark checkboxes complete based on this document.

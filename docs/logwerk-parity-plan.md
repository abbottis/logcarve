# LogWerk Parity Implementation Plan

Status: proposed 2026-11-01. Plan only — no application code changed.
Owner scope: `artifacts/task-inputs/logwerk-parity-owner-scope.md` (already authorized; no new approval loop).
Baseline: public checkout HEAD `70aab80` on `feature/logwerk-parity-2026-11-01`; application anchor `ffaf737` (owner-UX source).
Implementer for all later stages: Muse Spark 1.3 Contributor, medium effort, protections ON, sole writer, no subagents.

## 1. Feature matrix

| Capability | State |
| --- | --- |
| NCSA Combined Nginx/Apache streaming parse, UTC, HMAC pseudonyms, query discard | Already |
| SQLite WAL, import accounting, replay identity, retention, backup/restore | Already |
| Deterministic shared analytics (API/dashboard/tools), 77-rule bot catalog, conflict detector, 120-row synthetic fixture + goldens | Already |
| gzip streamed ingest, rotation files, file series, job accounting/cancel/replay | Needed (A) |
| Common, Apache vhost Combined, Nginx Extended presets; sampled autodetect + CLI override; bounded admin custom mappings | Needed (A) |
| Hostname/aliases + validated host filter/source mapping | Needed (A) |
| Nullable enriched fields (referrer path/host/protocol, cache, timing, MIME, TLS, HTTP version, host) + reprocess enrichment | Needed (B, C) |
| Local-admin original-IP view with default-full/selectable suffix-mask/pseudonym-only modes, at-rest protection, fail-closed key absence | Needed (B) |
| Measured latency/cache/MIME/version/host distributions in shared analytics | Needed (C) |
| SEO reports (bot 3xx/4xx/5xx per path, AI-only paths with caveat, referrer-path 404s, entry paths from journeys) | Needed (D) |
| Request journeys (HMAC+UA, 30-min gap, documented boundary) | Needed (E) |
| Expanded versioned security patterns, pseudonym rates/sequences, 401/403 clusters, baseline comparisons | Needed (F) |
| Full-result CSV+JSON export with metadata, formula protection, privacy labels | Needed (G) |
| Incremental follow+rotation, dashboard refresh on import, saved views, comparison windows | Needed (H) |
| Genuine offline country lookup (documented public source/version/license), optional ASN | Needed (I) |
| Locale preparation: central English keys, locale-ready formatting, coverage audit | Needed (J) |
| Browser file import/upload/drag-drop/import-trigger UI | ExplicitlyExcluded |
| Shipped translations or locale chooser | ExplicitlyExcluded |
| MCP product server, webhooks, paid/provider expansion, system cron/services, new public ports | ExplicitlyExcluded |
| LogWerk hash-modulo GeoIP fallback | ExplicitlyExcluded |
| Original IP / raw lines in API, exports, errors, model tools, Git | ExplicitlyExcluded |
| Coordinator-run proofs (fresh candidate image, protected browser, offline smoke, independent security review, Gitleaks) | VerifiedPending |

## 2. Architecture

Self-hosted existing stack only: Python 3.12+, FastAPI/Pydantic, Jinja2/htmx, Tailwind 4/daisyUI 5/Chart.js 4 (local build), SQLite WAL, Docker Compose.
No browser-only second engine, SPA, production Node service, Redis/PostgreSQL, or product MCP server.
Dashboard, external API, and internal tools share ONE deterministic analytics layer; models never generate SQL.

## 3. Accepted design (see ADR 0003)

- Original client IPs visible to local authenticated admin only; default full view, selectable suffix masking (IPv4+IPv6) or pseudonym-only. Pseudonyms stay the stable analytics identity in every mode.
- Server-side masking before any render; Settings change CSRF/session protected; API tokens can never access originals.
- Originals at rest use proven authenticated encryption with key separation; key absent means fail-closed unavailable while deterministic API keeps working. No IP/key in errors, URLs, history, API, tools, projections, or exports.
- Old records keep new fields nullable; discarded query values and pre-HMAC addresses are nonrecoverable. Matching old records gain enrichment only via read-only source reprocess — no duplicate events, no altered legacy HMAC/totals.
- GeoIP derived in memory before raw-IP discard/encrypt from a genuine local DB (documented source/version/license); `Unknown` stays `Unknown`; no IP leaves the host; no paid/public API.
- Request journeys are technical groupings (HMAC-client + sanitized UA, 30-min inactivity gap); labels say Requests/journeys, never visitors/sessions/people.
- Demo activation is reversible and local: preserves the 120-row fixture, auth, usage, and consumed allowance; no product calls or external exposure.

## 4. Staged tasks

All stages: new synthetic fixtures only; 120-row fixture bytes/goldens untouched; English docs; provenance recorded per import.

| Stage | Owner items | Files | Interfaces/dependencies | Meaningful tests |
| --- | --- | --- | --- | --- |
| T1 ingest + storage | A, B-schema | `app/ingestion/*`, `app/db/migrations/*`, `app/db/*`, `config/*` rules | CLI flags for preset override, custom mappings, host filter; migration + reprocess job | gzip/ratio bounds, preset fixtures, autodetect confidence, idempotent reprocess, key-absent fail-closed |
| T2 shared analytics | C, D, E, F | `app/analytics/*`, `config/bot_rules.yaml`, `config/security_rules.yaml` | Extended filter objects; versioned rule refs | Hand-counted latency/cache/MIME fixtures; journey boundary/truncation cases; exact-count security cases |
| T3 API + export | G, C–F surface | `app/api/routes_analytics.py`, `app/api/schemas.py`, new export job | Paginated/streamed CSV+JSON endpoints with metadata headers; token/site enforcement | Full-result (not page) export equality, formula-injection quoting, chat-off/no-key/offline run, token negatives |
| T4 admin web + locale | B-modes, H-views, J | `app/web/*`, `assets/src/*`, `config/locales/en.json` | Settings display-mode form (CSRF); saved views; locale-key coverage | Masking-before-render checks, CSRF tests, locale coverage audit, Playwright flows |
| T5 GeoIP + activation | I, H-follow | `app/ingestion/*` or `app/analytics/*` (lookup), candidate procedure docs | Local DB path config; documented public DB source/license; opt-in follow | Lookup unit tests incl. Unknown/private; NOTRUN runtime report when DB absent; restart/rotation/interruption tests |

Dependencies: T2 needs T1 schema; T3 needs T2; T4 needs T2/T3; T5 lookup plugs into T1 derive point, provable without the DB file.
New dependencies only with concrete purpose, pinned versions, lockfile, and primary-source license check.

## 5. Acceptance mapping

New IDs `PAR-01`–`PAR-10` (see `acceptance-criteria.md`) map A–J one-to-one and cite the existing ING/ANA/AUTH/API/PRIV/DB/UI/OPS criteria they extend.
Owner exclusions (no UI import, no translations) are explicit non-goals, not deferred debt.

## 6. First implementation task (promptable, bounded)

> T1a — gzip + preset ingestion on a scratch branch from `70aab80`: implement streamed gzip magic-detect/decompress with compressed/uncompressed/line/ratio/work bounds plus Common, Apache vhost Combined, and Nginx Extended presets with sampled autodetect and CLI override, using only new synthetic fixtures. Prove with unit/integration tests (bounds, replay identity, host-filter isolation) in `.venv`/`uv --locked` plus Ruff; preserve the 120-row fixture; no web/API/DB-schema changes yet; stop before commit for coordinator review.

Status 2026-11-01: T1a implemented on `feature/logwerk-parity-2026-11-01`
as a coherent slice commit (same branch, no rewrite), with 25 unit + 10
integration tests green, full unit/integration suite 569 passed, Ruff
clean; `uv --locked` BLOCKED by sandbox (coordinator re-runs). PAR-01
partially implemented at parser/import/CLI level; no web/API/schema
changes; independent re-inspection pending before T1b.

Correction 2026-11-01 (same branch, no amend): fixed gzip eof
tail/duplicate remainder, trailing NginxExtended order with `; charset`
MIME, genuine `regex==2026.9.29` engine timeout (locked via
`uv --offline`, `uv.lock` + `requirements.txt` regenerated, `.venv`
synced, `uv lock --check` clean), finite-nonnegative timings,
Combined-family default resolution, custom-vhost site default, limit
validation, timeout-abuse abort. 52 unit + 14 integration T1a tests,
full suite 600 passed / 2 env-skipped, Ruff clean. No T1b schema yet;
stopping for independent review.

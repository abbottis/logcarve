# LogCarve MVP implementation plan

- Status: **accepted**, 2026-10-29 by owner, subject to the six decisions in [ADR 0002](decisions/0002-mvp-scope-grill.md). T1 authorized; T2–T10 each need separate authorization.
- Origin: [technical spec v0.4](technical-spec.md), [MVP scope](mvp.md), [proposed architecture](architecture.md), [acceptance criteria](acceptance-criteria.md), area rules under `app/*/` and `tests/`.
- Scope contract: one site, one configured NCSA Combined source (Nginx and Apache samples), batch import, SQLite persistence, reproducible analytics, browser dashboard, internal Meta assistant AND independently usable authenticated read-only REST API. P1/P2 items stay out.

## Goal

Deliver the MVP in the smallest dependency-ordered slices, with deterministic analytics usable with chat disabled, no model key and no Internet, and with privacy and authorization boundaries tested at each affected slice.

## Success criteria

- Each slice names affected directories, acceptance IDs, test evidence and dependencies before work starts.
- Dashboard, external API and internal tools share one deterministic analytics layer; no duplicated metrics engine and no model-generated SQL.
- Import identity, migrations, query contracts, sessions, tokens, data egress and budget enforcement are designed once and reused by every later slice.
- Owner decisions on license/provenance, deployment and provider policy are recorded in `decisions/` before the slices that depend on them.
- Evidence lands in `verification.md` per acceptance ID; PASS, FAIL, BLOCKED and NOT RUN stay distinct.

## Approach

Build deterministic slices first (parser, storage, analytics, external API), then the assistant on top with fake providers, then the UI, then operations evidence. The assistant is a consumer of analytics, never a prerequisite for the API. Exact dependency versions are pinned during bootstrap from the tested Linux image, not assumed by this plan. Context7 spot-checks during planning confirmed daisyUI 5 requires Tailwind CSS 4 with CSS-based `@plugin` registration (no `tailwind.config.js`), and gave no evidence against the Python 3.12+ and FastAPI direction; the exact FastAPI/Pydantic floors are pinned at bootstrap.

## Design resolutions (proposed, require acceptance)

- Import identity: idempotency key is `(source_id, file fingerprint, record position such as byte offset or ordinal)`. A hash of normalized event contents alone is insufficient. Legitimate identical adjacent requests differ by position and survive; replaying the same file adds no events.
- Migrations: numbered SQL files in `app/db/migrations/` with a schema-version table and a documented backup-before-migrate step. One writer, transactional batches, parameterized repositories.
- Query contracts: validated Pydantic filter objects live in `app/analytics/`; `app/api/`, `app/web/` and `app/ai/` tools all call the same services. Missing duration stays `null` with `available: false`; never zero.
- Sessions versus tokens: local admin uses an Argon2-hashed password, server sessions, secure cookies and CSRF protection. Machine clients use separately hashed Bearer tokens with `analytics:read` scope, site binding, expiry and revocation. Analytics tokens grant no import, configuration or model-proxy capability.
- Data egress: fail-closed server-side gate over prompts, history, tool outputs, retries and replay. Only aggregates, rule references, time windows and sanitized evidence cross the gate. Raw lines, original IPs, query secrets and sensitive context never leave. Unknown providers, Contributor mode or unverified tiers block real-data transmission.
- Budget: server-side reservation and checks with warning, stop and daily limits (planning values 150/120/140, daily default zero). Exhaustion disables new model calls and leaves API and dashboard working.

## Steps

| Task | Outcome | Directories | Acceptance IDs | Evidence | Depends on |
| --- | --- | --- | --- | --- | --- |
| T0 — settle scope | Accepted plan and ADRs, explicit owner approval | `docs/`, `docs/decisions/` | GOV-01, GOV-02 (planning part) | Approval record, accepted ADR references | This plan, `/grill` |
| T1 — project and runtime baseline | Pinned Python, `pyproject.toml`, `uv.lock`, composition root, healthcheck, non-root Compose baseline, startup and config tests | `app/main.py`, `config/`, `tests/` | Foundation for OPS-01, OPS-02, QA-01 | Locked check commands pass, container healthcheck | T0, license decision |
| T2 — streaming parser and normalization | Combined fixtures normalize to expected fields; bounded rejects; read-only source resolution | `app/ingestion/`, `tests/fixtures/` | ING-01, ING-02, ING-03, PRIV-03 | Synthetic fixture tests with independent expected values | T1 |
| T3 — SQLite and repeatable import | Versioned migrations, transactional batches, idempotent import CLI, 30-day configurable UTC retention of owned data only, online-API backup with documented rotation and expiry, 100k-row measurement | `app/db/`, `app/ingestion/` | ING-04, ING-05, DB-01, DB-02 | Replay, interruption, restart tests; isolated restore test with integrity, analytics and retention-reapplication checks; hardware, duration, RAM, DB size | T2 |
| T4 — shared deterministic analytics | Typed filters, buckets, stable sorting, versioned bot and security rules, findings derived on read (no LLM, rule ID/version and evidence in every finding), coverage and quality metadata | `app/analytics/`, `config/bot_rules.yaml` | ANA-01, ANA-02, ANA-03 | Hand-calculated dataset; dashboard, API and tool equality for matching filters; reproducibility for same dataset, rule version, filters and window | T3 |
| T5 — auth and independent external API | Admin sessions, scoped site-limited tokens, versioned `/api/v1` routes, safe errors, external client working with chat off and no model key | `app/auth/`, `app/api/` | AUTH-01, AUTH-02, API-01 to API-04 | Token negative tests, offline-provider integration run | T4 |
| T6 — independent review of the first vertical slice | Read-only boundary review with file and line evidence | frozen diff or commit | QA-01 (parser, auth, retention, authorization) | Reviewer report and fix record | T5 |
| T7 — bounded assistant on fake providers | Allowlisted tools, egress gate, budget enforcement, failure-safe deterministic features | `app/ai/` | AI-03, AI-04, PRIV-01 to PRIV-03, COST-01, COST-02 | Captured mock payloads, tier-switch and concurrency tests; no real calls | T5, T6 |
| T8 — authorized real Meta smoke call | Three investigations with cited evidence and measured usage | `app/ai/`, synthetic data | AI-01, AI-02 | Redacted evidence, model, tool and evidence IDs | T7 plus verified account and explicit capped authorization |
| T9 — dashboard with local assets | Login, Overview, Security, Crawlers, Errors, Ask AI, Settings, Data Sources; both themes; no external requests | `app/web/`, `assets/`, `config/locales/` | UI-01 to UI-04, QA-02 | Playwright core paths, desktop and mobile light and dark screenshots, console and network review | T5 (shell first), T7 (Ask AI) |
| T10 — operations, scale and release | Fresh Compose install, persistence, benchmarks, final review, docs and demo materials | `docs/`, containers, synthetic data | OPS-01 to OPS-03, QA-01, GOV-03 | Install, restart, 100k and 1M measurements, reviewer closure | All above |

## Validation plan

- Locked project commands once the manifest exists: `uv run --locked ruff check .`, `uv run --locked ruff format --check .`, `uv run --locked pytest tests/unit tests/integration`, and `uv run --locked pytest tests/e2e` for UI slices.
- Redacted secret scan before any public push: `gitleaks dir . --redact=100`, plus history scan once commits exist.
- Highest-risk checks: import identity (replay versus legitimate duplicates), token and site authorization negatives, and the egress gate with adversarial URL, User-Agent and Referer input.
- Record actual command, environment, result and safe artifact references per acceptance ID. Missing implementation or credentials are BLOCKED or NOT RUN, never passing.

## Risks and open questions

- The remote repository exists (`abbottis/logcarve`, default branch `main`), but this checkout has no `.git` metadata and is not connected to it. The T1 integration path (clone versus initialize here and reconcile, without overwriting local work) must be settled before any commit, and worktree isolation needs a connected local repo with a first commit.
- The Docker daemon was unreachable from this machine at inspection, so container install evidence needs a working Linux host or VM.
- The local Python is 3.15.2 while the target image is pinned separately; the tested version is recorded at bootstrap.
- Owner decisions settled in [ADR 0002](decisions/0002-mvp-scope-grill.md): Apache-2.0 license with no unverified LogWerk reuse; private Linux x86-64 host/VM with Compose as install target; verify-then-capped-smoke for T8; separate clone with feature-branch reconciliation; 30-day configurable UTC retention with online-API backups; findings derived on read. Still unresolved: Meta account verification, real-provider execution, and publication gates.

## Sources

- [FastAPI release notes](https://fastapi.tiangolo.com/fr/release-notes/)
- [FastAPI settings and Python-version examples](https://fastapi.tiangolo.com/advanced/settings/)
- [daisyUI 5 install skill](https://github.com/saadeghi/daisyui/blob/master/skills/daisyui/install/SKILL.md)
- [daisyUI install guide](https://daisyui.com/docs/install/)

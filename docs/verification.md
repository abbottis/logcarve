# Verification record

## 2026-10-28 — scaffold

Product status: **NOT IMPLEMENTED**. pytest, API integration, Playwright, Docker, benchmarks and real Meta calls are **NOT RUN** because no product/runtime implementation exists. No account credit, effective service tier or provider credential has been verified.

Scaffold checks validate document/configuration/skill structure, not the product acceptance criteria.

| Check | Result | Evidence |
| --- | --- | --- |
| `muse --version`, interactive/exec/workflow/skill help | PASS | Installed 1.4.14 (1.4.14-R7309.1); launch/validation commands inspected without model calls |
| `muse skills validate .agents/skills/implement-feature --json` | PASS | `valid: true`, common-subset compatibility, no diagnostics |
| `muse skills validate .agents/skills/plan-feature --json` | PASS | `valid: true`, common-subset compatibility, no diagnostics |
| `muse skills validate .agents/skills/review-security --json` | PASS | `valid: true`, common-subset compatibility, no diagnostics |
| `muse skills validate .agents/skills/verify-release --json` | PASS | `valid: true`, common-subset compatibility, no diagnostics |
| Source/snapshot byte comparison and SHA-256 | PASS | Identical; checksum in `spec-provenance.md`; source unchanged |
| Python stdlib JSON/link/inventory checks | PASS | JSON parses, relative Markdown links resolve; 9 rule files, 121-line root, 4 skills, 62 scaffold files |
| Ruby `YAML.safe_load` and proposed-default assertions | PASS | Both YAML files parse; sources/AI/real-data flags off, daily budget zero, warning < stop <= total |
| `git check-ignore --no-index --stdin` with temporary Git metadata | PASS | 14 private/runtime paths ignored; 11 scaffold/future-hook paths preserved; no project Git initialization |
| Additional Skill-Creator `quick_validate.py` | BLOCKED | PyYAML unavailable in both available Python runtimes; native Muse validation above completed for all skills; no dependency installed |

No user-wide Muse settings were changed, MCP servers enabled, hooks installed, paid Meta requests made or external repository actions performed. Workflow documentation was retrieved through Context7's official-page index when direct web retrieval failed.

## 2026-10-28 — local Muse MCP setup

| Check | Result | Evidence |
| --- | --- | --- |
| Installed prerequisites | PASS | Muse 1.4.14, Node 22.23.4, npm 12.2.0 and installed Google Chrome |
| Pinned Chrome MCP installation | PASS | Published/installed `chrome-devtools-mcp` 1.12.0; dedicated user directory, package lockfile, install scripts disabled |
| Chrome JSON-RPC initialization and discovery | PASS | 32 tools discovered, separate isolated headless browser |
| Synthetic local browser smoke | PASS | Localhost page, explicit page ID, DOM snapshot, console/network tools and screenshot; only test-owned processes stopped |
| Native Muse startup with intended user MCP declarations | PASS | Local echo provider, then persisted settings without overrides; no Meta model calls |
| Muse interactive `/mcp` inventory | PASS | Final live inventory shows both `chrome-devtools` and `context7` connected; Context7 exposes `query-docs` and `resolve-library-id` |
| Settings merge and preservation | PASS | Existing preferences/model unchanged; backup created beside user settings; resulting file mode 0600 |
| Context7 OAuth endpoint | PASS | Correct `/mcp/oauth` endpoint reachable; anonymous initialization returned expected HTTP 401 |
| Context7 public documentation access | PASS | Public `/mcp`: initialization, 2 tools, library resolution and 4,587 characters of official FastAPI documentation retrieved without credentials |
| Context7 API-key authentication | PASS | Owner explicitly authorized key transmission/storage/relocation; both tools and actual FastAPI documentation retrieval passed with the supplied key; invalid-key control rejected |
| API-key storage and Muse startup | PASS | Local settings 0600; original key file preserved outside the repo under `~/.config/muse/secrets/CONTEXT7_API_KEY`; native echo-provider startup passed; Chrome/model preferences preserved |
| Optional Context7 OAuth connection | NOT COMPLETED | Owner approved basic profile/email access; consent UI/browser interaction stalled, user reported nonresponsive Allow. Both pending logins cancelled; no successful OAuth callback or account connection claimed |
| GitHub MCP | NOT CONFIGURED | Separate credentials/access decision deferred; no usable GitHub CLI authentication at inspection |

The repo's MCP example remains disabled and contains no credentials. The current user-level configuration authenticates Context7 with the owner-supplied API key. The earlier anonymous and OAuth results are retained as setup history; no OAuth success or private-library/account-quota audit is claimed. No Meta inference was used for these setup checks. Product acceptance criteria remain NOT IMPLEMENTED/NOT RUN.

## Future feature evidence

Record date, acceptance IDs, commit/diff reference, exact command, environment, PASS/FAIL/BLOCKED/NOT RUN, safe artifact path and reviewer where required. Keep operational artifacts under ignored `artifacts/`; commit only reviewed synthetic/redacted evidence. Never attach live logs, tokens, raw model traces or private sessions.

## 2026-10-29 — T1 project and runtime baseline (feature/t1-project-baseline)

Active checkout: separate clone at `/tmp/logcarve-t1`, branch `feature/t1-project-baseline`, base remote `main` at 836769b (rechecked before branching). No pushes; no `main` modification. Environment: macOS arm64 dev machine, uv 0.13.6, project Python 3.12.16 (uv-managed under `/tmp/uv-python`; the `~/.local/bin` version shim could not be linked under this sandbox — harmless, recorded). Resolved versions: fastapi 0.162.0, pydantic 2.14.2, pydantic-settings 2.16.2, uvicorn 0.54.0, httpx 0.28.1, pytest 9.2.0, ruff 0.17.3. All test secrets synthetic.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv sync`, `uv lock --check` | PASS | Fresh `uv.lock`; `.venv` on Python 3.12.16 |
| `uv run --locked ruff check .` | PASS | All checks passed |
| `uv run --locked ruff format --check .` | PASS | Files already formatted |
| `uv run --locked pytest tests/unit tests/integration` | PASS (unit) / NOT RUN (integration) | 5 passed: health liveness without model key, AI-disabled default, missing-secret failure, budget ordering, 30-day retention default; no integration tests exist yet |
| In-process uvicorn boot + `GET /healthz` | BLOCKED | Sandbox denies listening sockets (`operation not permitted` on bind); liveness covered by the TestClient test instead |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this machine (OrbStack socket permission denied); Dockerfile/Compose config unexecuted |
| Linux install verification | NOT RUN | No Linux host/VM available; macOS is the dev environment per ADR 0002 decision 2 |
| `gitleaks dir . --redact=100` (v8.30.1 standalone binary) | PASS with reviewed finding | 1 finding triaged as false positive: the `generic-api-key` rule matches a German section heading in `docs/technical-spec.md:787` (a cost-budget heading, no credential); no secret present, no rule weakened; Homebrew install unavailable under sandbox (no system writes performed) |

Acceptance impact: foundation only — no product criteria passed. OPS-01/OPS-02/QA-01 remain NOT RUN pending Linux execution and later slices.

## 2026-10-29 — T1 review correction: hermetic test environment (feature/t1-project-baseline)

Review finding: `tests/unit/conftest.py` isolated secrets only; other `Settings` fields leaked from the ambient environment (`AI_ENABLED=true` broke `test_ai_disabled_by_default`; `LLM_WARN_AT_USD=999` broke budget validation). Correction: the autouse fixture now clears every environment variable consumed by `Settings` (derived from `Settings.model_fields`, upper- and lower-case) plus the isolated cwd, and `monkeypatch` restores all of them after each test. Production validation in `app/config.py` is untouched. Focused regression tests added: `test_ambient_ai_enabled_true_is_isolated` and `test_ambient_llm_warn_at_usd_is_isolated` in `tests/unit/test_config.py`. Active checkout confirmed: `/path/to/original-development-checkout`, branch `feature/t1-project-baseline`; all pre-existing working-tree changes preserved.

Pre-fix reproduction (authentic failure, conflicting synthetic env):

| Check | Result | Evidence |
| --- | --- | --- |
| `AI_ENABLED=true LLM_WARN_AT_USD=999 uv run --locked pytest tests/unit -q` | FAIL (as expected) | 2 failed, 1 error: `test_ai_disabled_by_default` and `test_retention_default_is_thirty_days` raise `ValidationError` (`require llm_warn_at_usd <= llm_stop_at_usd <= llm_budget_usd`, input shows `llm_warn_at_usd: '999'`); `test_healthz_without_model_key` errors the same way |

Post-fix evidence (environment: macOS arm64, `UV_CACHE_DIR=/tmp/uv-cache`, project Python 3.12.16, all test secrets synthetic):

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 12 passed (11 config incl. 2 new isolation regressions plus secret/budget/retention checks, 1 health liveness) |
| `AI_ENABLED=true LLM_WARN_AT_USD=999 uv run --locked pytest tests/unit tests/integration -q` (conflicting synthetic env) | PASS | 12 passed; ambient values no longer leak |
| `uv run --locked ruff check .` | PASS | All checks passed |
| `uv run --locked ruff format --check .` | PASS | 45 files already formatted |
| `uv lock --check` | PASS | Resolved 27 packages; lockfile current |
| In-process uvicorn boot + `GET /healthz` | BLOCKED | Sandbox denies listening sockets; liveness covered by the TestClient test instead |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this machine (OrbStack socket permission denied); no container executed |
| Linux install verification | NOT RUN | No Linux host/VM available; macOS is the dev environment per ADR 0002 decision 2 |
| `/tmp/gitleaks-bin/gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | 1 finding triaged as false positive: `generic-api-key` matches the German section heading in `docs/technical-spec.md:787` (cost-budget heading, no credential); no secret present, no rule weakened |

Acceptance impact: test-hermeticity fix only — no product criteria passed. Secret/budget/retention negatives still enforce production validation. No pushes, no `main` modification, no provider calls, T2 not started.

## 2026-10-29 — T1 corrections record: all review findings committed (feature/t1-project-baseline)

The five reviewed T1 corrections: (1) `Dockerfile` — non-root user with owned `/data`, dependency-first install, `0.0.0.0` listener with loopback decided by the Compose mapping, corrected `uv export` provenance comment; (2) `app/config.py` — secrets required and non-empty (`Field(min_length=1)`), single `model_validator` enforcing full `warn <= stop <= budget` ordering instead of partial field validators; (3) `requirements.txt` — regenerated with `--no-emit-project`, dropping the `.` self-entry; (4) `tests/unit/test_config.py` — hermetic secret/budget/retention coverage plus ambient-isolation regressions; (5) `tests/unit/test_health.py` — `monkeypatch` fixture with module reload under the synthetic environment, no `os.environ` leakage. `tests/unit/conftest.py` (autouse full-`Settings` env isolation) supports all of the above. Production validation is intact: missing/empty secrets and disordered budgets still fail clearly.

Committed results: `af01beb` holds `tests/unit/conftest.py`, `tests/unit/test_config.py` and the prior verification entry. Working-tree tested results (this entry): the full tree including the four remaining files passes `uv run --locked pytest tests/unit tests/integration -q` with 12 passed in both clean and conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) synthetic envs, `ruff check` and `ruff format --check` clean, `uv lock --check` current. The tested implementation is unchanged since those runs, so this evidence carries onto the commit below. Environment: macOS arm64, `UV_CACHE_DIR=/tmp/uv-cache`, project Python 3.12.16, all test secrets synthetic.

| Check | Result | Evidence |
| --- | --- | --- |
| `/tmp/gitleaks-bin/gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | 1 finding triaged as false positive: `generic-api-key` on the German heading `docs/technical-spec.md:787`; no secret present, no rule weakened |
| In-process uvicorn boot + `GET /healthz` | BLOCKED | Sandbox denies listening sockets; liveness covered by the TestClient test instead |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable (OrbStack socket permission denied); corrected Dockerfile/Compose config unexecuted |
| Linux install verification | NOT RUN | No Linux host/VM available; macOS is the dev environment per ADR 0002 decision 2 |

Acceptance impact: T1 baseline corrections recorded and committed; foundation only, no product criteria passed. OPS-01/OPS-02/QA-01 remain NOT RUN pending Linux execution and later slices. No pushes, no `main` modification, no provider calls, T2 not started.

## 2026-10-29 — T2 streaming Combined parser and normalization (feature/t2-combined-parser)

Branch from 92bb694; T1 history preserved. New code: `app/ingestion/combined.py` (explicit `nginx_combined`/`apache_combined` presets sharing the Combined grammar with preset-specific escape handling; UTC normalization with original offset minutes; HMAC-SHA256 client pseudonyms; query discard; Referer host minimization; secret-pattern masking; `duration_ms` always `None`), `app/ingestion/sources.py` (pydantic `SourceConfig`: admin-configured IDs, absolute approved roots, relative paths only; traversal/absolute/NUL rejected at validation; symlink escape, missing-file and directory rejected at resolution; read-only open; file identity for replay), `app/ingestion/stream.py` (fixed-chunk line reader bounded to line-limit plus one chunk; per-line record-or-rejection streaming; `ImportReport` with accepted/rejected counts, per-reason accounting and bounded masked diagnostics). Fixtures: `combined/nginx_combined.txt` (10 valid lines), `combined/apache_combined.txt` (6 valid lines), `adversarial/combined_mixed.txt` (9 rejected + 5 accepted injection/sensitive cases), hand-derived `expected/combined_records.json`. No SQLite, analytics, auth, UI or model code; no new dependencies (`uv lock --check` clean, 27 packages).

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration` (clean env) | PASS | 39 passed (12 T1 + 27 T2: preset expectations incl. reference line, identical-request distinction, ordered positions, adversarial reason counts, opaque injection text, invalid bytes, bounded diagnostics, oversized placeholder, unknown-format/empty-key refusal, source-unchanged hash, batched streaming, resolution/traversal/symlink/file-identity negatives) |
| Same suite with `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 39 passed; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 51 files formatted (3 findings in new T2 code fixed before commit, no rule weakened) |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `generic-api-key` false positive on the German heading in `docs/technical-spec.md:787` |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |

Acceptance impact: ING-01 (both presets normalize to independent expectations), ING-02 (streaming bounded reader, oversized-line/target/UA/referer rejections, exact counts, bounded masked diagnostics), ING-03 (admin source IDs, approved roots, traversal/symlink rejection, read-only verified by hash) and the parser portion of PRIV-03 (HMAC pseudonyms, query discard, Referer minimization, secret masking, null duration) verified. Database-dependent criteria (ING-04/05 replay-persistence, DB-01/02) and independent security review (QA-01) remain pending. No pushes, no `main` modification, no provider calls.

## 2026-10-29 — T2 correction: single oversized marker per physical line (feature/t2-combined-parser)

Original failure: `list(iter_raw_lines(BytesIO(b"x" * 20), max_line_bytes=10))` yielded two `RawLine(0, None)` markers for one physical line; an oversized final line spanning multiple chunks double-reported the same way. Cause: the overflow path yielded the marker immediately and set `skipping=True`, and the EOF path yielded a second marker for the same line. Correction in `app/ingestion/stream.py`: the marker is now yielded once at line end (newline while skipping, or EOF while skipping); overflow only records the start offset. Bounded memory (buffer capped at line limit plus one chunk), offsets and subsequent-line handling preserved.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/unit/test_combined_parser.py -k oversized` | PASS | 6 passed: one-chunk EOF, multi-chunk EOF (forced 7-byte reads), oversized-then-valid with byte offsets, and both end-to-end `ImportReport` counts (`lines_read` 2, accepted 1, rejected 1, `oversized_line`) |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 44 passed in both environments |
| `ruff check .`, `ruff format --check .` | PASS | All checks passed; 51 files formatted |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `technical-spec.md:787` false positive |

Acceptance impact: ING-02 accounting strengthened (exactly one rejection per oversized physical line). No pushes, no `main` modification, no provider calls, no T3 work.

## 2026-10-29 — T3 SQLite persistence and repeatable batch import (feature/t3-sqlite-import)

Branch from ed0c99e; T2 history preserved. New code: `app/db/migrations/0001_initial.sql` + `migrations_runner.py` (numbered migrations, idempotent reruns, bookkeeping table self-created, backup-before-migrate on pending upgrades of non-empty DBs), `database.py` (WAL + foreign keys + bounded busy timeout; `writer_transaction` takes the reserved lock via `BEGIN IMMEDIATE` and raises `WriterBusy` past the bounded wait), `repositories.py` (parameterized site/source/import/event writes, `INSERT ... ON CONFLICT DO NOTHING` replay semantics with exact inserted counts), `importer.py` (SHA-256 content fingerprint streamed with bounded memory; replay identity `(source_id, fingerprint, byte_offset)` — no inode/mtime or content dedup; per-batch bounded transactions so interruptions keep committed batches; source size-change flagged as `source_changed`), `retention.py` (configurable UTC cutoff, owned `requests` rows only, import reports kept), `backup.py` (online backup API, 0600 permissions, isolated restore with integrity checks, rotation), `cli.py` (local `import`/`retention`/`backup`/`restore` subcommands; HMAC key from `HMAC_KEY` env only). Documented procedures in `docs/backup-restore.md`. No analytics, auth, UI or model code; no new dependencies (`uv lock --check` clean, 27 packages).

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 65 passed in both (44 T2 + 21 T3: migration idempotency + backup-before-migrate with pre-migration rows, backup perms/overwrite-refusal/isolated restore/rotation, retention cutoff/boundary/owned-only, replay ×2 incl. identical-content-different-path without inode reliance, identical-adjacent distinct positions, interrupted→failed→completed-resume without duplicates, restart persistence, source-appended flag, bounded concurrent-writer `WriterBusy`, retention→replay reinserts only deleted, restore→retention reapplied, CLI exit 0 with exact counts, 100k benchmark) |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 64 files formatted |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `technical-spec.md:787` false positive |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |

Measured 100k import (ING-05; synthetic seeded log, generated at test time, never committed): 100,000 lines → 98,969 accepted / 1,031 rejected-by-design malformed; file 11,059,497 B; database 45,854,720 B including `-wal`/`-shm`; elapsed 1.9 s import (53,197 rows/s); peak RSS delta +5.8 MiB (bounded streaming, batches of 1,000). Environment: macOS arm64 dev machine, macOS 27.0.1, project Python 3.12.16, `UV_CACHE_DIR=/tmp/uv-cache`. These are observed values on this machine, not performance guarantees.

Acceptance impact: ING-04 (same-file and same-content replay insert nothing; identical adjacent requests survive with distinct positions), ING-05 (100k measured import above), DB-01 (versioned migrations, restart persistence, transactional batches, interrupted recovery, integrity-checked restore) and DB-02 (UTC retention of owned data only with replay/restore interaction, online backup with protected permissions and documented rotation/expiry) verified. Continuous ingestion/rotation automation, Docker/Linux execution and independent security review (QA-01) remain pending. No pushes, no `main` modification, no provider calls, T4 not started.

## 2026-10-29 — T3 correction: backup/restore/rotation input safety (feature/t3-sqlite-import)

Original failures, reproduced before the fix: (1) `backup_database()` with a missing source reported success and created an empty source database; (2) `restore_database()` with a missing backup likewise created an empty backup and reported successful restoration; (3) `rotate_backups()` deleted unrelated `*.sqlite3` files and other databases' backups (only `keep` survivors remained, unscoped). Correction in `app/db/backup.py`: inputs must already exist as regular files and pass a read-only integrity check before anything is created; sources are opened read-only; destinations are created exclusively (`O_CREAT|O_EXCL`) with `0600` from the start with overwrite refusal retained, and an incomplete owned output is removed on failure; rotation requires a non-empty `db_stem` and only touches regular non-symlink files named `<stem>-backup-*.sqlite3` / `<stem>-pre-migrate-*.sqlite3`. The CLI passes the database stem through; procedures updated in `docs/backup-restore.md`.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/unit/test_db_backup.py` | PASS | 9 passed: missing/invalid source and backup inputs fail with no files created, rotation preserves unrelated/other-DB/symlink entries, perms/overwrite/isolated-restore behavior retained |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 70 passed in both environments |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 64 files formatted |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `technical-spec.md:787` false positive |

Acceptance impact: DB-02 backup safety strengthened (fail-closed inputs, scoped rotation). Independent review (QA-01) remains pending. No pushes, no `main` modification, no provider calls, no T4 work.

## 2026-10-29 — T4 shared deterministic analytics (feature/t4-deterministic-analytics)

Branch from e29920a; T3 history preserved. New code: `app/analytics/contracts.py` (validated `AnalyticsFilter`/`TimeWindow`/allowlisted sorts; UTC-only, half-open windows, bounded limit/offset), `queries.py` (parameterized aggregates, allowlisted `ORDER BY`, tie-breakers, bounded distinct-value scans, half-open UTC buckets with empty-bucket fill, coverage that never double-counts replays and lists every import state), `rules.py` (validated `Rule`/`RuleSet` with case-insensitive claim matchers) plus versioned `config/bot_rules.yaml` (v2, five crawler claims with hand-authored provenance) and `config/security_rules.yaml` (v1, sensitive-path + repeated-client-error candidates), `service.py` (single consumer entry: summary, timeseries, top paths/referrers, crawler claims, security findings with rule ID/version, evidence, filters, window, observation time, counts, coverage and limitations; duration `available: false` for Combined-only data, never fabricated). One justified dependency: PyYAML 6.0.3 for rule files (`pyproject.toml`, `uv.lock` + regenerated `requirements.txt`). No HTTP routes, auth, UI or model code.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 91 passed in both (70 T3 + 21 T4: contract validation, rule loading/matching/validation, hand-calculated totals/status/bytes, tie-broken paths with pagination, minimized referrers, hour/day buckets with empties/boundaries/equivalent instants, claimed-bot findings with claim wording, security candidates with evidence, replay-proof coverage, failed-import warnings, backup/restore equivalence) |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 72 files formatted |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `technical-spec.md:787` false positive |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |

Acceptance impact: ANA-01 (one shared layer; hand-calculated totals/filters/buckets/ties stable and reproducible), ANA-02 (Combined-only duration stays null with explicit `available: false`; no averages fabricated), ANA-03 (versioned rule IDs, claimed-bot wording, investigation-candidate findings with evidence filters, coverage and limitations; no people/session/indexing/attack inferences). Cross-consumer (dashboard/API/tool) integration and independent review (QA-01) remain pending until those consumers exist. No pushes, no `main` modification, no provider calls, T5 not started.

## 2026-10-29 — T5 authentication and independent external API (feature/t5-auth-api)

Branch from ee9b583; T4 history preserved. New code: `app/db/migrations/0002_auth.sql` (admin users/sessions, scoped tokens; existing data untouched), `app/auth/` (Argon2id passwords per current argon2-cffi docs; opaque server-side sessions with per-session CSRF tokens; SHA-256-hashed `lc_` bearer tokens with site binding, scope, expiry, revocation; token shown once; `auth` CLI reading secrets from env only), `app/api/` (versioned `/api/v1` analytics endpoints over shared services with explicit response schemas; protected OpenAPI JSON; restricted `/readyz`; public minimal `/healthz`; safe `code/message/request_id` envelopes with no SQL/paths/secrets; 366-day window enforced with 367-day rejection test; UTC-only timezone enforcement). One justified dependency: argon2-cffi 25.1.0 (`pyproject.toml`, `uv.lock`, regenerated `requirements.txt`); sessions use opaque IDs so no signing library was needed. `clients/logcarve_api_client.py` (stdlib-only external client) plus curl/n8n guidance and verified usage in `docs/external-api.md`. Compose now requires `SESSION_SECRET`/`HMAC_KEY` from shell/`.env` (fail-fast interpolation); image packages `config/` rule files.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 112 passed, 2 skipped in both (19 T5: Argon2 roundtrip/failures, session lifecycle/expiry, credential non-enumeration, token issue/verify/expiry/revoke/hash-secrecy, rate limits; missing/invalid/expired/revoked/wrong-scope/cross-site/cross-source tokens, summary/crawlers/findings vs shared services, error groups, hour buckets, 367-day/timezone/sort validation errors sanitized, admin login/logout/CSRF, token/session cross-authorization refusal, session expiry, login rate limit, admin CLI, openapi protection/docs disabled). 2 skips: loopback-bind tests, sandbox-denied; covered by the Docker run below |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 88 files formatted |
| `gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `technical-spec.md:787` false positive |
| Isolated Compose smoke (`-p logcarve-t5-smoke`, image `logcarve:t5-smoke`, engine 29.8.2 linux/**arm64**) | PASS | `docker build`, `up -d`, `/healthz` 200 `ai_enabled:false`; in-container import 10/10; admin create + token issue via CLIs; real loopback HTTP: summary totals `{requests:10, errors_4xx:2, errors_5xx:1, bytes_total:3322, bytes_measured:9}` with `duration.available:false`, crawlers/findings 200, no-token/bogus-token 401 with `request_id`, `/readyz` 401; admin login → `/readyz` 200 `schema_version:2` → logout → `/readyz` 401; stack `down -v` + image removed, no residue. **ARM64 only: x86-64 NOT verified** |
| Linux install verification | NOT RUN | No Linux host/VM available |
| Provider-failure checks | PENDING | No model integration exists yet; repeat after T7 |

Acceptance impact: AUTH-01 (Argon2 passwords, server sessions, secure cookie flags, CSRF, bounded login rate limits, generic errors), AUTH-02 (scoped `analytics:read` Bearer [REDACTED] site-bound with expiry/revocation, token shown once, site/source enforcement) and API-01–04 (versioned documented analytics GETs matching shared services, server-side boundaries incl. 367-day rejection, sanitized envelopes, metadata/coverage/warnings; analytics tokens authorize nothing else; chat disabled, no model key; stdlib client + compose smoke vs real HTTP) verified. T1 hermetic fixture promoted to `tests/conftest.py` after the conflicting-env run exposed the gap. Dashboard/tool integration and independent security review (QA-01) remain pending. No pushes, no `main` modification, no provider calls, no production deployment, T6 not started.

## 2026-10-31 — T6 security corrections (feature/t6-security-fixes)

Branch from 55ef06d; T5 history preserved. Fixes for the six T6 review findings (supplied review record; independent reinspection still pending). No new dependencies (`uv lock --check` clean, 32 packages).

- M1 — token/session expiry as instants: `app/auth/tokens.py` gains `parse_expiry`/`normalize_expiry`; `issue_token` normalizes any offset to canonical UTC storage and rejects naive/malformed values; `verify_token` and `get_session` compare parsed UTC instants with fail-closed on malformed/naive stored values. `POST /api/v1/admin/tokens` rejects naive `expires_at` (400) and returns the normalized UTC value. Auth CLI inherits fail-closed via `issue_token`.
- M2 — read-only login: `app/api/deps.py` gains `StoreUnavailable`; `check_password` opens the store read-only, and missing/corrupt/uninitialized stores map to a safe structured 503 `store_unavailable` with `request_id`. Successful session creation still writes normally. No files or directories are created on the unauthenticated path.
- M3 — username timing: unknown usernames run the normal Argon2 verify path against a lazily built fixed dummy hash; the result is always `None`. Generic messages and rate limiting unchanged.
- L1 — exact window: `TimeWindow` compares the exact `timedelta` against 366 days instead of floored `.days`.
- L2 — allowlisted diagnostics: `app/db/importer.py` maps failures to `interrupted:io_error|storage_error|writer_busy|import_failed`, keeps `source_changed_during_import` plus new `source_content_mismatch`; `sanitize_error_summary` keeps only allowlisted segments at the shared analytics read boundary (`app/analytics/queries.py:coverage`), replacing legacy free-text summaries with `diagnostic_withheld:legacy_format`. Quality warnings preserved.
- L3 — source consistency: post-import digest re-hash compared against the recorded fingerprint (an open descriptor alone does not prevent in-place writes); size or content changes set `source_changed` with explicit codes, keep committed batches queryable, and never report a silent clean completion. Semantics documented in the `importer` module docstring; replay guarantees preserved (changed files re-import under the new fingerprint).

| Check | Result | Evidence |
| --- | --- | --- |
| L3 repro-first: new same-size-change test vs unfixed `importer.py` (fix stashed) | FAIL (as expected) | `source_changed=False, error_summary=None`, silent clean completion on a same-size mid-import rewrite |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 127 passed, 2 skipped in both (112 T5 + 15 T6: offset/negative-offset/exact/naive/malformed/legacy expiry, dummy-verify path, API offset/naive/malformed issuance, missing/corrupt/empty-store 503 with no file creation or modification, exact 366-day boundary + 1µs + 12h rejection, sentinel failure code + API-visible scrub, legacy scrub + segment preservation, same-size mismatch with replay) |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 90 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current |
| `/tmp/gitleaks-bin/gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `generic-api-key` false positive on the German heading in `docs/technical-spec.md:787` |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this machine |
| Linux install verification | NOT RUN | No Linux host/VM available; dev machine is arm64 macOS |
| Provider-failure checks | PENDING | No model integration exists yet; repeat after T7 |

Acceptance impact: AUTH-01 (fail-closed store handling, enumeration-hardened login), AUTH-02 (offset-correct, normalized, fail-closed token expiry), API-01/03 (safe 503 envelope, normalized issuance contract, exact window bound, scrubbed quality metadata), DB-01/ING-04 (flagged consistency with preserved replay/recovery semantics) strengthened with regression tests. x86-64 execution NOT verified (arm64 only). Independent review closure (QA-01) explicitly not claimed here; no pushes, no `main` modification, no provider calls, no T7 work.

## 2026-10-31 — T6 correction round 2: reader digest (L3) and residual store failures (M2)

Continuing on `feature/t6-security-fixes` from `ba562f5`. Two findings only; M1/M3/L1/L2 left untouched. No new dependencies (`uv lock --check` clean, 32 packages).

- L3 — consumed-bytes digest: `app/ingestion/stream.py` feeds every raw byte pulled from the source stream (content, newlines, rejected lines, skipped oversized data) into a running SHA-256 at chunk-read time; `ImportReport.consumed_sha256` is set only on full consumption to EOF (interruptions leave it unset) and surfaced on `ImportResult`. `app/db/importer.py` compares the reader digest against both the pre-import fingerprint and a fresh final digest: mismatch flags `source_content_mismatch` (never a silent clean completion), including a transient same-size rewrite restored before the final hash; a change landing after the reader finished flags `source_changed` with correctly attributed rows. Bounded memory, offsets, accounting and interruption/replay behavior preserved; semantics documented in the `importer` module docstring.
- M2 residual — unavailable stores: new `read_store` context manager in `app/api/deps.py` maps only `sqlite3.Error`/`OSError` on read-only handles to the narrow `StoreUnavailable` signal (arbitrary programming exceptions untouched); a single `store_unavailable_handler` in `app/api/errors.py` returns structured 503 `store_unavailable` with matching body/header `request_id` and no paths, SQL or exception text. Applied to Bearer verification, source-membership check, session-cookie reads, all eight analytics endpoints, admin token listing and login (via the handler). `GET /readyz` opens the store inside its guarded block, keeping its existing structured 503 `not_ready` envelope for query-time failures.

| Check | Result | Evidence |
| --- | --- | --- |
| L3 repro-first: transient rewrite-and-restore test vs unfixed code (app stashed) | FAIL (as expected) | Restored file matched the recorded fingerprint yet the import reported clean; fixed code flags `source_content_mismatch` |
| `uv run --locked pytest tests/unit tests/integration` clean + conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 135 passed, 2 skipped in both (127 T6 + 8 new: transient rewrite/restore with replay, clean unchanged input with matching digest incl. rejected/oversized bytes, interrupted consumption without digest, Bearer/session/readyz/query-time/source-check 503s with no SQL leak and no file creation) |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 89 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current |
| `/tmp/gitleaks-bin/gitleaks dir . --redact=100` (v8.30.1) | PASS with reviewed finding | Only the known `generic-api-key` false positive on the German heading in `docs/technical-spec.md:787` |
| `docker build` / Compose up | BLOCKED | `docker info` client 29.8.2 works; daemon socket `~/.orbstack/run/docker.sock` permission-denied from this sandbox — an access denial, not an engine failure; no container executed |
| Linux install verification | NOT RUN | No Linux host/VM available; dev machine is arm64 macOS |
| Provider-failure checks | PENDING | No model integration exists yet; repeat after T7 |

Acceptance impact: DB-01/ING-04 (reader-proved consistency with replay/recovery guarantees; committed batches kept and queryable on mismatch) and AUTH-01/02/API-01–04 (uniform safe 503s across Bearer/session/readyz/read paths with request-ID parity and no store creation or disclosure) strengthened with regression tests. Closed findings M1/M3/L1/L2 untouched and still passing. x86-64 execution NOT verified (arm64 only). Independent reinspection still pending; no pushes, no `main` modification, no provider calls, no T7 work.

## 2026-10-31 — external client findings-route correction (fix/external-client-findings-route)

Owner-authorized correction after canonical workspace consolidation. Parent candidate: `c4a7bc4`; active workspace: `/path/to/logcarve`.

Original failure: the previously sandbox-skipped real HTTP client test executed after relocation and returned HTTP 404 for `findings`. A fresh temporary Git export of `c4a7bc4` reproduced the same failure, establishing that it predated the move. The client assembled `/api/v1/findings`, while the documented and implemented endpoint is `/api/v1/security/findings`.

Correction: `clients/logcarve_api_client.py:fetch` maps the logical `findings` endpoint to `security/findings` when constructing the request URL. CLI options, JSON output keys, Authorization handling, filters and server routes are unchanged. No new dependency or test was added: the existing external-client integration tests already exercise the complete real-loopback request sequence and invalid-token rejection.

Environment: macOS ARM64, project-local Python 3.12.16, uv 0.13.6. All fixture data and credentials are synthetic. Loopback sockets are available in this execution environment.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/integration/test_external_client.py -q` | PASS | 2 passed over real loopback HTTP; default summary/crawlers/findings flow and invalid-token rejection |
| `uv run --locked pytest tests/unit tests/integration -q` with a clean environment | PASS | 137 passed, zero skipped; `artifacts/client-findings-fix-2026-10-31/pytest_clean.txt` |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 137 passed, zero skipped; `artifacts/client-findings-fix-2026-10-31/pytest_conflicting.txt` |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 88 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current |
| Gitleaks 8.30.1, fully redacted, all tracked candidate files exported to an isolated directory | PASS with reviewed finding | Scanner exit 1; only the previously reviewed `generic-api-key` false positive on `docs/technical-spec.md:787` (cost-budget heading); ignored private/runtime files were not read |
| Gitleaks 8.30.1, fully redacted Git history across all refs | PASS with reviewed finding | Scanner exit 1; the same heading in initial scaffold commit `629f6cc`; no new finding |

Acceptance impact: API-01/API-03 working external-client evidence and API-04 invalid-token rejection strengthened. Prior relocation failures remain historical evidence; the client-route defect is now corrected and the full suite passes. Existing T6 review evidence applies to its reviewed candidate; this client-only routing correction does not change authentication, authorization or parser behavior. Docker/x86-64, model/provider and later release gates are unchanged. No push, `main` modification, product-provider call, deployment or T7 work.

## 2026-10-31 — T7 bounded assistant on fake providers (feature/t7-bounded-assistant)

Owner-authorized T7 scope from `docs/remaining-build-plan-2026-10-31.md`. Branch from `3f932e7`; candidate: `0c0840320dee84689b7105a19dab48d48d24c99b`. New code: `app/ai/gate.py` (allowlisted meta / muse-spark-1.3 / standard, verified-policy and real-data flags, revalidated per request), `app/ai/egress.py` (minimized allowlisted evidence serializer; fail-closed scan of prompts/history/questions/results/retries/replay over IPs, log lines, query secrets, credentials, product tokens, PEM, oversize; IP-shape masking inside evidence only), `app/ai/tools/definitions.py` (seven allowlisted read-only tools, `extra="forbid"` arguments, server-side site/source scope, bounded results with traceable tool-call IDs), `app/ai/providers/` (adapter contract plus scripted network-free fake with full outgoing capture), `app/ai/budget.py` (durable `ai_spend` ledger via migration `0003`: daily bucket plus cumulative lifetime stop/total, atomic reservation, release/charge, restart-safe), `app/ai/service.py` (bounded tool-calling loop with per-step egress, trusted-scope override of model-supplied site/source/time, timeout/cancellation, conservative floor charge after any dispatch, English local errors), `app/ai/prompts/assistant_system.md`, `app/api/routes_chat.py` (admin session + CSRF, analytics Bearer [REDACTED] rejected, per-session rate limit and concurrency bound; enabled-without-backend reports unavailable, never a fake answer). No new dependencies (`uv lock --check` clean, 32 packages). No real product provider transport exists; no real calls made.

Review-note corrections applied during implementation: lifetime charged-plus-active accounting separate from the daily bucket (UTC rollover cannot reset the global stop); conservative charge (measured spend floored at one full attempt) on timeout/cancellation/provider failure instead of a free release; IPv6 candidate filter (`::`, 3+ colons or hex letter) so ISO-8601 timestamps and bare times pass while real addresses still match; investigation-scope override for site/source/time with focused regressions for each.

Environment: macOS ARM64, project-local Python 3.12.16, uv 0.13.6 (`UV_CACHE_DIR=/tmp/uv-cache`). All fixture data and credentials synthetic.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 191 passed, 2 skipped (pre-existing loopback-bind skips); 54 new T7 tests: gate allowlist/tier-switch, egress forbiddens/timestamp/evidence regressions, budget accounting/rollover/total-cap/4-thread no-double-spend, tools allowlist/scope/hostile fixtures, service evidence/scope-override/replay/cancel/timeout/failure/budget/disabled, chat auth/CSRF/Bearer-rejection/disabled/unavailable/injected-fake/rate-limit |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 191 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 106 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current; no new dependency |
| Gitleaks 8.30.1, fully redacted, isolated export of the candidate | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history across all refs | PASS with reviewed finding | Same heading in `629f6cc`; no new finding |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this sandbox (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |
| Real Meta provider call | NOT RUN | No real transport implemented; T8-gated |

Acceptance impact: AI-03 (allowlist, validated bounded arguments, hostile URL/UA/Referer with no execution, unknown-tool rejection), AI-04 (timeout/cancel/provider-failure/budget-exhaustion leave summary API green), PRIV-01 (captured mock payloads scanned; raw IPs/log lines/secrets/tokens blocked or masked), PRIV-02 (unknown/Contributor/unverified tiers and mid-session switches block), PRIV-03 (minimized evidence, HMAC/query-discard inheritance, owned-data-only ledger), COST-01 (daily/lifetime/warn/stop/total, concurrency-safe reservation, measured charges), COST-02 (exhaustion error with deterministic API intact) verified for the fake-provider scope. AI-01/02 stay NOT RUN (no real transport). Independent review (QA-01) explicitly not claimed; candidate frozen for review. No push, `main` modification, production change, public exposure or T9 work. No provenance additions: all code original, no third-party imports.

## 2026-10-31 — T7 corrections R1–R6 plus route/import alignment (feature/t7-bounded-assistant)

Independent review `artifacts/reviews/t7-21cc6da-independent.md` of candidate `21cc6da` reran the suite (**193 passed, zero skipped**, including the two loopback cases) and reproduced six defects plus two integration corrections. Recorded here as corrections required, not independent closure. Bounded correction slice authorized; both existing commits preserved, no history rewrite.

Corrections, all with reproduce-first durable regressions on the real service/HTTP paths (19 new probes failed on `21cc6da` before the fix):

- R1: the live gate is now revalidated immediately before every dispatch (later steps, retries, replay); the validated model binds each investigation result. Regression: tier flip after step one yields exactly one captured request and `egress_blocked`.
- R2: address detection uses real `ipaddress` parsing over colon-bearing tokens instead of word-boundary shape heuristics: `::1`, `::`, `[::1]`, `fe80::1`, `2001:db8::1`, `fe80::1%eth0`, `::ffff:203.0.113.7` and full forms block/mask, while ISO-8601 timestamps and bare times pass. Captured outgoing prompts are additionally proven free of raw addresses with an independent parser-based scan.
- R3: provider waits run on daemon workers with a polling deadline and a fixed worker capacity (8): control returns at the timeout even when the adapter ignores cancellation, external cancellation during a wait is prompt, saturation fails closed immediately, and repeated timeouts recover for a fast adapter. No thread is forcibly killed.
- R4: response shape (text/usage types and signs), per-response (8) and total (32) tool bounds, declared-usage-vs-requested-bounds, answer length and cumulative history bounds are validated before executing work; violations are safe `InvestigationError`s (never raw `EgressViolation`s) with full step holds settled.
- R5: each dispatch composes the actual bounded prompt, reserves a conservative per-step hold (UTF-8 byte-length input upper bound plus explicit protocol overhead plus output maximum), reconciles only that step's measured increment, and keeps the full hold on unknown/invalid usage. Declared usage beyond the requested bounds fails closed. The byte-length bound replaces the chars/4 average; pricing stays an explicit planning-only estimate with real transport blocked (`PRICING_VERIFIED = False`, `select_provider` raises).
- R6: trusted actor (`admin` only), site existence, source membership and the shared exact `TimeWindow` contract are validated over a read-only handle before any reservation or dispatch; invalid scope yields safe errors with zero fake requests and zero new reservations. Model-supplied scope stays overridden afterwards.
- Route alignment: chat moved to `POST /api/v1/chat/ask` with unchanged admin-session/CSRF authorization (old path now 404); prior chat tests retargeted.
- Lazy AI imports: `app.ai.service` and siblings import inside the authenticated enabled-chat path only; a simulated unavailable AI import leaves `create_app`, `/healthz` and analytics reads green with AI off, and chat reports `ai_unavailable` (503) instead of failing startup.

Environment: macOS ARM64, project-local Python 3.12.16, uv 0.13.6 (`UV_CACHE_DIR=/tmp/uv-cache`). All fixture data and credentials synthetic. No real product provider transport/calls; account prerequisites noted separately, no real call authorized in this slice.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 222 passed, 2 skipped (pre-existing loopback-bind skips); 31 new correction tests |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 222 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 107 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current; no new dependency |
| Gitleaks 8.30.1, fully redacted, isolated export of the candidate | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history across all refs | PASS with reviewed finding | Same heading in `629f6cc`; no new finding |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this sandbox (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |
| Real Meta provider call | NOT RUN | No real transport; fake-only slice |

Acceptance impact: R1/R6 strengthen PRIV-02 and AI-03 (per-dispatch gate, scope-first); R2 strengthens PRIV-01 (all address forms); R3/R4 strengthen AI-04 (bounded waits, bounded outputs, safe errors); R5 strengthens COST-01/02 (per-step holds, incremental reconciliation, fail-closed growth stop). AI-01/02 remain NOT RUN. Independent reinspection of the frozen correction candidate is the next gate. No push, `main` modification, production change, public exposure or T9 work. No provenance additions: all code original, no third-party imports.

## 2026-10-31 — T7 reinspection and R5 rollover correction (feature/t7-bounded-assistant)

Independent reinspection `artifacts/reviews/t7-a2f08d6-reinspection.md` of candidate `a2f08d6` ran **224 passed, zero skipped** and closed the original R1–R6 probes, but reproducibly left one R5 boundary wrong: the UTC budget day was computed once before the loop, so post-midnight dispatches kept charging yesterday even when today's budget was exhausted. Recorded as corrections required, not release approval. Only this targeted correction authorized; all history and tests preserved.

Correction: `run_investigation` takes an optional trusted `clock` callable and computes the UTC budget day at each dispatch/reservation (`_utc_today`; naive readings treated as UTC). Observation metadata still comes from the stable `now`; production passes neither, so live dispatches read the live clock. Each reservation remains charged to its own dispatch day via the existing reservation linkage. Deterministic injection preserved: `now` alone still freezes the day for existing tests.

Regressions (real service path, all failed on `a2f08d6` via negative control, all pass now): rollover into an already exhausted next day (exactly one dispatch, `budget_reached`, next-day ledger untouched); rollover into available next-day allowance (both days charged, observation timestamp stable); lifetime stop binding across midnight despite fresh daily room (two dispatches, per-day charges, cumulative total exact).

Environment: macOS ARM64, project-local Python 3.12.16, uv 0.13.6 (`UV_CACHE_DIR=/tmp/uv-cache`). Synthetic fixtures only. No real product provider transport/calls; fake-only slice.

| Check | Result | Evidence |
| --- | --- | --- |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 225 passed, 2 skipped (pre-existing loopback-bind skips); 3 new rollover tests |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 225 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 107 files formatted |
| `uv lock --check` | PASS | 32 packages, lockfile current; no new dependency |
| Gitleaks 8.30.1, fully redacted, isolated export of the candidate | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history across all refs | PASS with reviewed finding | Same heading in `629f6cc`; no new finding |
| `docker build` / Compose up | BLOCKED | Docker daemon unreachable from this sandbox (OrbStack socket permission denied) |
| Linux install verification | NOT RUN | No Linux host/VM available |
| Real Meta provider call | NOT RUN | No real transport; fake-only slice |

Acceptance impact: COST-01 daily/lifetime accounting now correct across UTC midnight; no other acceptance claim changes. Final T7 reinspection is the next gate. No push, `main` modification, production change, public exposure, T9 work or real provider calls. No provenance additions.

## 2026-10-31 — T7 independent closure at 4ecc1d3 (feature/t7-bounded-assistant)

Independent coordinator closure recorded in `artifacts/reviews/t7-4ecc1d3-closure.md`: the clock-only correction from `a2f08d6` to `4ecc1d3` was reviewed with a clean tracked tree; the writer made no implementation/test/configuration edits and no real provider call in this step.

| Check | Result | Evidence |
| --- | --- | --- |
| Independent full locked suite on `4ecc1d3` | PASS | **227 passed, zero skipped**; 4 pre-existing deprecation warnings; includes real loopback client tests unavailable in the writer sandbox |
| Midnight-boundary probes (trusted advancing clock, synthetic DB) | PASS | Rollover into exhausted next day: `budget_reached`, exactly one dispatch, next-day ledger untouched; rollover into available day: two dispatches, one charge per day, observation timestamp stable |
| Original R1–R6 probes on `a2f08d6` | PASS | Closed per the prior reinspection; only the delta (budget-clock selection/dispatch-day calculation plus regressions) changed |
| Real Meta provider transport/call | NOT RUN | No real transport exists; no real call authorized in this slice |

Acceptance impact: T7 fake-provider findings closed for this slice (AI-03, AI-04, PRIV-01–03, COST-01/02 for the fake scope). AI-01/02 remain NOT RUN. Pricing stays an explicit unverified planning estimate. The owner separately confirmed account/team, credits, access and effective Standard handling; real execution still needs the prepared capped-run authorization and a protected product key. This is not release approval and claims no dashboard, container or Linux x86-64 verification. T9 dashboard planning may proceed from this baseline. No push, `main` modification, production change or public exposure.

## 2026-10-31 — T9-A dashboard shell and Overview (feature/t9-dashboard)

Owner-authorized part-A implementation of `docs/t9-dashboard-plan.md` (taste-reviewed) plus coordinator-steered hardening (safe redirects, theme tokens, menu button, centralized browser strings, logout success-check with CSRF refresh, sandbox-kept browser config, function-scoped e2e fixture). New code: `app/web/routes.py` + `headers.py` + `locales.py`, Jinja2 templates, local asset pipeline, `tests/integration/test_web_overview.py` (9 tests), `tests/integration/test_web_hardening.py` (8 tests) plus shared `tests/integration/conftest.py`, `tests/e2e/` Playwright suite. Python: Jinja2 3.1.6 runtime (+ regenerated `requirements.txt`) and pytest-playwright 0.10.0 / Playwright 1.64.1 dev pinned in `uv.lock`. No duplicate analytics, no model transport, no part-B views, no source/upload API. Provenance and changelog updated.

Environment: macOS ARM64, project Python 3.12, uv 0.13.6, node 22.23.4 / npm 12.2.0 (local `/tmp/npm-cache` after the root-owned `~/.npm` cache denied writes), synthetic fixtures only. One disclosure: macOS quarantine xattrs were cleared on the downloaded test-browser files during launch diagnosis; no other OS/browser protection was changed, no user-wide setting was touched, and the briefly added `--no-sandbox` test override was removed — the maintained fixture keeps `chromium_sandbox=True` with a 15 s timeout.

| Check | Result | Evidence |
| --- | --- | --- |
| `npm run build` (vendor + JS + Tailwind CSS) | PASS | `app/web/static/app.css` (90,685 B), vendor JS, 2 WOFF2 + OFL texts, 18 SVGs + ISC text, `vendor/PROVENANCE.md` |
| `uv run --locked pytest tests/integration/test_web_overview.py -q` | PASS | 9 passed: public login + CSP, session redirect, Bearer-does-not-open-dashboard, hand-checked totals (11 requests incl. attack line, 3 / 1), service agreement, empty/invalid/unknown-site states, fragment auth/shape, logout lock, adversarial escaping |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 241 passed, 2 skipped (pre-existing loopback-bind skips), incl. 9 web-overview and 8 web-hardening tests |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 241 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 118 files formatted |
| `uv lock --check` | PASS | 40 packages, lockfile current |
| `tests/e2e` Playwright suite (this sandbox) | BLOCKED | Fixture keeps `chromium_sandbox=True` (15 s timeout, no `--no-sandbox` anywhere); the browser dies at launch here with `FATAL:base/apple/mach_port_rendezvous_mac.cc:159 ... bootstrap_check_in ... Permission denied (1100)` → SIGTRAP — an enclosing-sandbox denial, not a product defect. Coordinator verified the same pinned Chromium launches protected-mode cleanly outside this sandbox; exact command `uv run --locked pytest tests/e2e -q` is coordinator-run |
| `node ./scripts/check_no_external.mjs` | PASS | No fetch-vector external references in served assets/templates |
| Gitleaks 8.30.1, fully redacted, isolated candidate export | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history (17 commits) | PASS with reviewed finding | Same heading; no new finding |

Acceptance impact (claimed only where observed): UI-01 (central catalog, explicit UTC/Berlin display timezone), UI-02 (login/nav/filter/tables/charts over shared services), UI-04 (local assets + CSP headers, fetch-vector proof), AUTH-01 session/CSRF paths (redirects, logout, Bearer refusal). UI-03 and QA-02 need the coordinator-run browser evidence (`uv run --locked pytest tests/e2e -q` outside this sandbox). No push, `main` modification, production change, public exposure or part-B work.

Review note for T10: `.gitignore` covers `/app/web/static/{css,js,fonts}/*` but not the sibling build outputs (`static/app.css`, `static/vendor/`, `static/icons/`); the part-A commit carries sources plus the currently un-ignored outputs while `static/js|fonts` stay ignored and regenerate via `npm run build`. Align the ignore/build layout and add the Dockerfile build step when containerizing.

## 2026-10-31 — T9-A corrections A1–A6 (feature/t9-dashboard)

Bounded corrections for the independent review `artifacts/reviews/t9a-edec1b1-independent.md` (243 passed here; coordinator protected-mode E2E 3 failed / 1 passed with documented defects). History preserved; `edec1b1` untouched. The owner-provided protected product key was neither read nor used; no model calls. Strict CSP and `chromium_sandbox=True` kept throughout; no `--no-sandbox`, no suppressed console errors, no CSP weakening.

- A1: htmx meta config now disables eval, injected indicator styles and inline-style settling (`attributesToSettle` without `style`), sets `historyCacheSize: 0` with `refreshOnHistoryMiss`, all per current upstream docs; indicator styling is local CSS.
- A2: filter inputs render normalized UTC `datetime-local` values; fragments answer `HX-Push-Url` with the canonical page URL (never `/partials/...`), so reload/back/forward keep the applied window, coverage and data together.
- A3: private HTML carries `Cache-Control: no-store` (static assets exempt); with zero htmx snapshot cache, post-logout Back reloads through the server session check instead of restoring analytics.
- A4: navigation is a narrow overlay panel (static sidebar on desktop) with backdrop/Escape handling and a compact wrapping header; tables keep their own horizontal scroll.
- A5: daisyUI `light`/`dark` themes bind the agreed sky/slate tokens, icons are inlined (currentColor-aware), and charts use theme-readable ticks/grid with re-render on theme change.
- A6: e2e uses semantic heading locators and adds functional Apply/reload/back/forward, logout+Back, menu geometry, computed-color, chart, console and network checks.

Environment: macOS ARM64, project Python 3.12, uv 0.13.6, node 22.23.4 / npm 12.2.0, synthetic fixtures only.

| Check | Result | Evidence |
| --- | --- | --- |
| `npm run build` + `node ./scripts/check_no_external.mjs` | PASS | Vendor/CSS/JS/icons rebuilt; no fetch-vector external references |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 250 passed, 2 skipped (pre-existing loopback-bind skips), incl. 9 new correction regressions |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 250 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 119 files formatted |
| `uv lock --check` | PASS | 40 packages, lockfile current |
| `uv run --locked pytest tests/e2e -q` (this sandbox) | BLOCKED | Same enclosing-sandbox denial as recorded: `mach_port_rendezvous ... Permission denied (1100)` → SIGTRAP at browser launch with `chromium_sandbox=True`. Coordinator-run outside this sandbox |
| Gitleaks 8.30.1, fully redacted, isolated candidate export | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history | PASS with reviewed finding | Same heading in `629f6cc`; no new finding |

Acceptance impact: A1–A6 server-side behavior verified (CSP posture, canonical filter URLs, no-store/logout denial, overlay markup, token-bound CSS, inlined icons, semantic locators). Browser-observed proof (console-clean swaps, reload/back/forward content, post-logout Back, 360px geometry, computed colors, working charts) needs the coordinator-run e2e. No push, `main` modification, production change, public exposure, part-B work or provider-key use.

## 2026-10-31 — T9-A residual corrections (feature/t9-dashboard)

Bounded follow-up to the reinspection `artifacts/reviews/t9a-ed35543-reinspection.md` (252 passed here; 2 passed / 3 failed protected e2e). No part B, no key reads, no provider calls; strict CSP and `chromium_sandbox=True` kept; no quarantine changes; no whole-page overflow clipping.

- Layout: intrinsic-size guard chain (cards, bodies, stats, chart frames at `min-width: 0`; wrapping stat copy; canvas `max-width: 100%`; `table-scroll` bounded scrollers on all four Overview table containers), debounced chart re-render on viewport resize, and the observation-window line moved into the swapped fragment so partial updates refresh it.
- Filter e2e: awaits the real 200 partial response plus the swapped observation window, then asserts canonical URL, displayed window and changed KPI data across Apply/reload/back/forward.
- Color e2e: OKLCH-aware conversion to sRGB comparing rendered colors against the live `--color-sky/slate` tokens (±5, no stale RGB constants), plus ≥4.5 body-text and Apply-button contrast in both themes; chart datasets asserted row-for-row against the accessible tables with charts re-checked after the theme switch.

Environment: macOS ARM64, project Python 3.12, uv 0.13.6, node 22.23.4 / npm 12.2.0, synthetic fixtures only.

| Check | Result | Evidence |
| --- | --- | --- |
| `npm run build` + `node ./scripts/check_no_external.mjs` | PASS | Rebuilt with guards/indicator/icon CSS; no fetch-vector external references |
| `uv run --locked pytest tests/unit tests/integration -q` (clean env) | PASS | 252 passed, 2 skipped (pre-existing loopback-bind skips), incl. window-refresh + width-guard regressions |
| Same suite with synthetic `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 252 passed, 2 skipped; hermetic fixture holds |
| `uv run --locked ruff check .`, `ruff format --check .` | PASS | All checks passed; 119 files formatted |
| `uv lock --check` | PASS | 40 packages, lockfile current |
| `uv run --locked pytest tests/e2e -q` (this sandbox) | BLOCKED | Unchanged enclosing-sandbox denial (`mach_port_rendezvous ... Permission denied (1100)` → SIGTRAP with `chromium_sandbox=True`); not retried beyond one signature confirmation. Coordinator-run outside this sandbox |
| Gitleaks 8.30.1, fully redacted, isolated candidate export | PASS with reviewed finding | Only the known `generic-api-key` false positive on `docs/technical-spec.md:787` |
| Gitleaks 8.30.1, fully redacted Git history | PASS with reviewed finding | Same heading in `629f6cc`; no new finding |

Acceptance impact: residual server-side behavior verified; browser-observed layout/geometry/color proof needs the coordinator-run e2e. No push, `main` modification, production change, public exposure, part-B work or provider-key use.

## 2026-10-31 — T9A independent closure at 656c5e1 (feature/t9-dashboard)

Independent coordinator closure recorded in `artifacts/reviews/t9a-656c5e1-closure.md`: protected Chromium E2E **5 passed** (actual filter Apply with KPI 10→8, reload/back/forward, canonical URL, private logout+Back, 360px overlay geometry, actual palette with ≥4.5 body/button contrast, visible accessible-table vs live Chart data equality, both themes, clean console/network). Application suite at unchanged `54ed772`: **254 passed, zero skipped** (later commits are test helpers and evidence only). Separate coordinator probe: actual chart totals 10, width 360 both themes, zero console errors, screenshots inspected. No keys, provider calls, push, main modification or deployment. T9A exit satisfied for the local scope; whole-UI criteria need part B.

## Follow-up fixes on d1f1d54 (same slice, uncommitted)

- Narrow-window KPI corrected to the independently hand-derived 8 events (missing-page 09:15:32Z and the 07:14Z 500 fall outside [10:00Z,12:00Z); the other eight run 10:02:03Z–11:04Z). No analytics change; 10-wide expectations and navigation/data assertions unchanged.
- Real contrast defect fixed in the token layer: light-theme `--color-primary-content` is now slate-950 over sky-600 (≈5.0:1, AA) instead of white (≈4.0:1); dark sky-400 already pairs with slate-950. Semantic sky/slate palette unchanged, no lowered thresholds. Rebuilt assets; suites re-run green (252 passed, 2 skipped, both envs).
- Test-only e2e fix (no app change): the chart/table helper now opens the real `<details>` summaries and asserts visible tables, comparing cells against both the server JSON and live `Chart.getChart(...).data`. Focused syntax/Ruff/format checks pass; unchanged app-suite evidence reused. Coordinator reruns protected e2e.

## 2026-10-31 — T9-B remaining views (feature/t9-dashboard, uncommitted)

Part-B implementation over the shared analytics layer (no second engine): Security/Crawlers/Errors with bounded pagination and evidence links, Ask AI over session/CSRF with honest disabled/unavailable states (starter populates only, plain-text answers, server-contract evidence links), read-only Settings/API guidance and Data Sources (CLI docs, no upload/path input). Canonical filters preserve source/matchers/paging/bucket across Apply (offset resets deliberately); overview tables honor limit/offset with position notes; side-nav links adopt the newly applied shared window on all data pages; failed Applies show a visible alert and keep previous results. No product-key read/use, no provider calls, no push/main change.

- `npm run build` — PASS (Tailwind/daisyUI rebuild, JS copied, `node --check` clean on ask/nav/filter sources and built copies).
- `uv run --locked pytest tests/integration/test_web_partb.py -q` — **17 passed** (envelope contract incl. source mapping, Ask scope/contract/plain filter, scope preservation, finding links, paging honesty, reversed-window 400 + failure wiring, CSP/no-store/nav).
- `uv run --locked pytest tests/unit tests/integration -q` — **269 passed, 2 skipped** (both skips: loopback sockets unavailable in writer sandbox, `test_external_client.py`; environmental, unrelated).
- `uv run --locked ruff check .`, `ruff format --check .`, `uv lock --check`, `node ./scripts/check_no_external.mjs` — PASS.
- `uv run --locked pytest tests/e2e --collect-only` — 9 tests collected, no syntax errors. Protected Chromium run is BLOCKED in the writer sandbox (known Mach bootstrap denial); coordinator runs `uv run --locked pytest tests/e2e -q` outside, covering 4 new real-interaction tests (Ask starters/disabled send, errors Apply scope + same/cross-page nav sync, reversed-window visible alert with stale results, overview paging note).

Acceptance impact: whole-UI dashboard criteria now implemented for the local scope pending independent browser proof. No push, `main` modification, production change, public exposure or provider-key use. No new dependencies; all code original plus pinned local vendor bundles already recorded.

## 2026-10-31 — T9-B independent-review corrections (feature/t9-dashboard, uncommitted)

Corrects the bounded defect set from `artifacts/reviews/t9b-4aad188-independent.md` (sole writer, no subagents, no key reads, no provider calls, no T8 work, protections unchanged).

- `uv run --locked pytest tests/unit tests/integration -q` — **275 passed, 2 skipped** (both skips: loopback sockets unavailable in the writer sandbox, `test_external_client.py`; environmental).
- `uv run --locked ruff check .`, `ruff format --check .`, `uv lock --check`, `node ./scripts/check_no_external.mjs`, `npm run build`, `node --check` on touched browser scripts — PASS.
- `uv run --locked pytest tests/e2e --collect-only` — 12 tests collected. Protected Chromium execution is BLOCKED in the writer sandbox (known Mach bootstrap denial); coordinator runs `uv run --locked pytest tests/e2e -q`, covering new Ask success/failure/Apply interaction, Errors reload-on-page, cross-page nav sync and structured console matching.
- Gitleaks NOT RUN in the writer sandbox (no binary); coordinator scans candidate/history with `/tmp/gitleaks-bin/gitleaks`.

Acceptance impact: Security/Crawlers evidence rendering, Ask transport, per-route canonicals, safe-400 bounds, sample labelling and server-generated chat hrefs are implemented with passing suites; browser proof of the corrected paths awaits the coordinator protected run. No push, `main` modification, production change, public exposure or provider-key use. No new dependencies.

## 2026-10-31 — T9-B reinspection residuals (feature/t9-dashboard, uncommitted)

Focused residuals from `artifacts/reviews/t9b-0fc4722-reinspection.md` (sole writer, no key reads, no provider calls, no new features, protections unchanged).

- `uv run --locked pytest tests/unit tests/integration -q` — **277 passed, 2 skipped** (both skips: loopback sockets unavailable in the writer sandbox, `test_external_client.py`; environmental).
- `uv run --locked ruff check .`, `ruff format --check .`, `uv lock --check`, `node ./scripts/check_no_external.mjs`, `npm run build` — PASS.
- `uv run --locked pytest tests/e2e --collect-only` — 14 tests collected. Protected Chromium execution is BLOCKED in the writer sandbox (known Mach bootstrap denial); coordinator runs `uv run --locked pytest tests/e2e -q`, covering new populated narrow Security, real Next/Previous paging, active-nav reload filters and exact-match 409/503 console assertions.
- Gitleaks NOT RUN in the writer sandbox (no binary); coordinator scans candidate/history with `/tmp/gitleaks-bin/gitleaks`.

No push, `main` modification, production change, public exposure or provider-key use. No new dependencies.

## 2026-10-31 — T8 mocked-transport preparation (feature/t8-meta-adapter)

Bounded real-adapter preparation with mocked HTTP only, per
`artifacts/reviews/t8-plan-review.md` mandatory corrections (sole
writer, no subagents, no key open/read/use, no provider calls, no
push/main changes, no deployment, protections unchanged).

- `uv run --locked pytest tests/unit tests/integration -q` — **311 passed, 2 skipped** (both skips: loopback sockets unavailable in the writer sandbox, `test_external_client.py`; environmental, pre-existing).
- New/changed suites: `tests/unit/test_meta_adapter.py` (endpoint allowlist, exact integer pricing, usage subsets/total/model/status, typed call correlation incl. reasoning acceptance, native stub-opener transport incl. TLS/redirect/timeout/bounds, pre-encoding decoded validation, verbatim-body Bearer dispatch, send-boundary binding, full binding), `tests/unit/test_smoke_allowance.py` (lifetime caps, widening refusal, narrowing applies atomically, failed-attempt counting, pre-overspend cost stop, restart persistence without reset, last-slot atomicity), `tests/integration/test_t8_preparation.py` (hand-derived A/B/C expectations, exact replay, web verbatim filters, mocked real-path investigation with call_id replay + verified settlement, wire-value bypass rejection, static answer guard, default dry-run, offline real-run entry incl. foreign-dataset and blocking-config refusals).
- `uv run --locked python scripts/smoke_meta.py` (default dry-run) — **OK: 3 investigations, 6 requests, $0.163224 estimated**; key file never opened, network untouched (mock transport only).
- `uv run --locked ruff check .`, `ruff format --check .`, `uv lock --check`, `npm run build`, `node ./scripts/check_no_external.mjs` — PASS. No new dependencies (stdlib transport).
- `uv run --locked pytest tests/e2e --collect-only` — 14 tests collected; protected Chromium execution is BLOCKED in the writer sandbox (known Mach bootstrap denial); coordinator runs the protected E2E/browser matrix.
- Gitleaks NOT RUN in the writer sandbox (no binary); coordinator scans candidate/history before delivery/publication.

Acceptance impact (mock level only): AI-03/AI-04/PRIV-01/PRIV-02/COST-01/COST-02 paths covered against the mocked transport with T7 regressions kept; ANA-01/ANA-03 replay equality proven for exact filters incl. GET/get, OPTIONS with literal `*`, mixed-case referrer and source/window/paging. R1–R7 review rework verified: protocol-faithful `type:function/parameters` tools, native opener (TLS context via HTTPSHandler, redirect refusal, stub-signature transport tests), reasoning acceptance with model/status/total validation, pre-encoding decoded egress validation, atomic narrowing caps, allowance enforced on every real invocation incl. UI/API chat, verified-config respect with foreign-dataset refusal, sanitized application results + failure ledger requiring actual tools/evidence. AI-01/02 stay NOT RUN — no real execution or spending authorized; no ledger/result artifact produced here (defaults live under ignored `data/`).

## 2026-10-31 — T8 reinspection fixes (feature/t8-meta-adapter)

Bounded preflight/output-safety correction per `artifacts/reviews/t8-a0a022a-reinspection.md` (disposable synthetic sources only, no key/network/spend).

- `uv run --locked pytest tests/unit tests/integration -q` — **319 passed, 2 skipped** (environmental socket skips, pre-existing).
- Follow-up minimization + IDs: fixed product `reasoning:{"effort":"low"}` on the wire (Context7 `/docs/features/responses`), reservation unchanged via MAX_OUTPUT coverage; validated bounded `response_id`/`call_id` preserved in result/usage/ledger/application artifacts; real user text is question + scope only with single typed replay (marker-once captured-body assertion).
- Review probe `artifacts/reviews/probe_smoke_preflight_safety.py` now reports `existing_staging_accepted: false, existing_source_overwritten: false, same_aggregate_foreign_data_accepted: false`.
- New regressions: staging sentinel/symlink refusal with targets untouched, byte-exact fixture reuse across restarts, aggregate-equivalent foreign-DB refusal with store and staging untouched, 0600 owned outputs with symlink/collision/pre-existing refusal, pre-existing ledger aborting the entry before any dispatch.
- `uv run --locked python scripts/smoke_meta.py` (default dry-run) — OK; `ruff check .`, `ruff format --check .`, `uv lock --check` — PASS.
- Preflight now: exclusive no-follow 0600 staging creation or byte-exact read-only reuse (never truncate/move/delete/follow); read-only recognition of existing stores before any migration/seed/key load (exact fixture SHA256 fingerprint, completed/unflagged imports, single site/source, no foreign rows); outputs exclusively claimed 0600 with symlink/collision refusal and pre-dispatch validation, preserving actual ledgers. Settings/DataSources shared-nav state loss stays carried to T10, untouched here.
- AI-01/02 and any real execution remain NOT RUN and unapproved.

## 2026-11-01 — T10 local demo slice (feature/t10-local-demo, uncommitted)

Bounded local build per `docs/t10-local-demo-plan.md` with coordinator corrections
(`artifacts/reviews/t10-plan-review.md`, `artifacts/reviews/t10-smoke-pre-review.md`;
sole Muse writer, no subagents, no product key read, no AI enable, no provider/account/
connectivity probe, no spend, no push/main/prod). App code change: `app/web/routes.py`
only (Settings/Data Sources carry the shared window state via `_optional_nav_query`;
invalid params never 400 there).

- `uv run --locked pytest tests/unit tests/integration -q` — **335 passed, 2 skipped**
  in clean AND `AI_ENABLED=true LLM_WARN_AT_USD=999` envs (skips: loopback sockets
  unavailable in the writer sandbox, `test_external_client.py`; environmental,
  pre-existing pattern). New suites: `test_nav_shared_window.py` (5 Settings/Data
  Sources roundtrips + matcher locality), `test_demo_probe.py` (7 probe verdicts incl.
  interrupted-init recovery), `test_demo_init.py` (4 temp-export init/idempotency/
  permissions/symlink-refusal); `tests/e2e/test_nav_roundtrip.py` (all-entries click
  roundtrips) for coordinator execution.
- `uv run --locked ruff check .`, `ruff format --check .`, `uv lock --check` — PASS.
  No new dependencies. `node:22.23.4-bookworm-slim` / `python:3.12.16-slim-bookworm`
  pins; coordinator verified both manifests exist amd64+arm64 and the bookworm aliases.
- `sh -n` on all `scripts/demo/*.sh` + `scripts/smoke_demo.sh` — PASS; every embedded
  Python heredoc and all 27 `python -c` one-liners compile-checked before commit.
- Coordinator protected Chromium E2E against the final UI/nav source — **15 passed,
  zero skipped, 13.18s** (one upstream pytest fixture deprecation warning). Tested
  tree pinned in `artifacts/reviews/t10-e2e-tested-tree.json`; writer re-compared all
  99 hashes after final edits — identical, evidence reused without re-running the
  blocked browser. Coordinator independently ran the clean locked suite — **337 passed,
  0 skipped, 16.87s** (writer sandbox skips 2 socket tests environmentally: 335 + 2).
  Fresh-image browser/layout proof stays PENDING actual Docker build.
- Docker/Compose smoke (`scripts/smoke_demo.sh`, isolated internal-network project,
  authoritative fixture digest, label-identified resources, no secret argv) and the
  persistent demo lifecycle (`scripts/demo/*`) are BLOCKED in the writer sandbox
  (OrbStack socket denied); coordinator executes and appends evidence here.
- Scale figures reused verbatim from `artifacts/reviews/scale-summary.md` (single cold
  samples; security derivation ~10.26 s at 1 M); no SLO invented. T8 real calls stay
  NOT RUN/unapproved. Linux x86-64 native stays NOT RUN (ARM64 initial demo).

Acceptance impact: OPS-01/OPS-02 demo/smoke runners implemented, coordinator-gated;
UI-02 shared-nav-loss leg closed with TestClient + Playwright twins (E2E green);
QA-01 partial (independent review pending after commit). No public URL, submission,
purchase, or paid call.

## 2026-11-01 — T10 coordinator runtime evidence (reported, append-only)

Coordinator executed what the writer sandbox cannot (Docker 29.8.2 linux/arm64,
Compose 5.5.0). No owner key read, real Meta calls/spend, source writes,
push/main/public/prod by the review.

- Fresh tracked-export image build — PASS (log: `t10-a59bc2a-smoke.log`).
- Persistent AI-off demo RUNNING on `127.0.0.1:8080` (left running; writer must
  not stop/reset it). `health.sh` PASS schema 4.
- Fresh-image protected browser — **28 cases PASS**: all views/themes/1440+360,
  chart totals 30, navigation all entries, no console/external/failed requests.
  Evidence: `artifacts/reviews/t10-container-browser/results.json`.
- Independent internal-network offline probe — PASS: API 3/HTML 7, auth
  negatives, import 30/replay 0, non-root 10001, source read-only, restart
  persistence, backup 0600, isolated restore + retention, source unchanged,
  no default route. Evidence: `artifacts/reviews/t10-offline-container-results.json`,
  executable `probe_t10_offline_container.py`.
- Conflicting suite — **337 passed, 0 skipped, 16.53s**; E2E 15 pass with UI tree
  hashes unchanged; Gitleaks dir+history: only the known `technical-spec.md:787`
  false positive.
- ONE runner defect handed back (fixed on this branch after `a59bc2a`): Docker 29
  `internal: true` networks suppress host-port publishing, so host-curl smoke
  phases time out despite an internally healthy app. Correction: all smoke HTTP
  checks moved inside the isolated network via tracked
  `scripts/smoke_offline_probe.py` (`--wait` + full pass, label-identified
  resources, isolation failure aborts); host browser gate stays on the persistent
  demo. No isolation weakening, no new proxy/dependency, no host protection change.

Acceptance impact: OPS-02 offline proof exists independently (coordinator) and is
now reproducible via the corrected runner (coordinator rerun pending); OPS-01
loopback/non-root/read-only proven on the running demo; UI-02 browser matrix green
on the fresh image. T8 real calls NOT RUN/unapproved; Linux x86-64 NOT RUN.

## 2026-11-01 — T10 coordinator follow-up evidence (reported, append-only)

- External client, maintained stdlib `clients/logcarve_api_client.py
  --endpoint all` against the persistent demo — success: summary 30,
  crawlers, findings; isolated client env carries no model key. Evidence:
  `artifacts/reviews/t10-external-client-results.json`.
- Actual `reset.sh` — success with replay 0: requests 30, admin_users 1,
  api_tokens 1, ai_spend 0, smoke_allowance 0, smoke_holds 0, full row
  digests unchanged; source hash + mtime unchanged. Existing zero-ledger
  state tested, plus code review shows no reset writes to usage/allowance.
  Evidence: `artifacts/reviews/t10-demo-reset-results.json`.
- Protected browser screenshots (overview light 1440, security dark 360)
  visually inspected, acceptable.
- Persistent demo left RUNNING; writer must not rerun/stop/reset it.

## 2026-11-01 — T10 offline-probe correction (feature/t10-local-demo, uncommitted)

Coordinator repro against the running persistent demo (demo-only auth, no key/paid
calls) found two helper defects before Docker: raw `+00:00` window values decoded
to spaces (summary/crawlers/findings 400), and the shared cookie-jar opener let a
logged-in session + missing CSRF answer 403, masking the token-only 401. Fixed in
tracked `scripts/smoke_offline_probe.py` (`urlencode` window params, stateless
Bearer opener, schema-valid chat body) with new `test_offline_probe.py` isolation
regression (4 tests: encoding roundtrip, jar-free Bearer opener, session/Bearer
separation, chat schema). Internal smoke `ports:` removed entirely (Docker 29
publishes nothing there); loopback exposure asserted on the persistent profile
only. Locked suites: **339 passed, 2 skipped** (environmental socket skips) in
clean AND conflicting envs. E2E tree re-compared 99/99 identical. Rerun of the
finite smoke is coordinator-owned; persistent demo untouched.

## 2026-11-01 — T8 authorized real smoke, run ONCE (coordinator evidence)

Owner explicitly authorized the prepared 3-investigation / 12-request / USD 1
cap (synthetic fixture only), then a stop point. Coordinator executed reviewed
`scripts/smoke_meta.py` once on 2026-10-31 23:12:08–23:12:26 UTC against
`muse-spark-1.3` (`https://api.meta.ai/v1/responses`); no automatic rerun.
Safe summary only (`artifacts/reviews/t8-real-smoke-2026-11-01.md`); writer
never read the key or raw traces.

- A completed: 5 tool/evidence envelopes, actual provider response/call IDs,
  GPTBot 7 / ClaudeBot 2, 12 observed requests, timing unavailable.
- B completed: 4 tool/evidence envelopes, missing page 5 requests, referrer
  groups 3+2, window total 10.
- C FAILED CLOSED with `output_limit_reached` (fixed history-bound message,
  no retry): tool history hits HISTORY_MAX_CHARS 4000 before second dispatch.
- Lifetime usage: 3/3 investigations, 5/12 provider requests, held 0; ledger
  charged 39,557 microUSD = USD 0.039557 estimate (not a provider invoice).
- AI-01 now has actual bounded Meta/tool evidence. AI-02 is INCOMPLETE/FAIL
  (2 of 3) — not passed, no false pass.
- Confirmed display-only cost bug (separate from settlement): the final step
  is double-counted in returned usage (e.g. A displayed 0.025820 vs charged
  0.017071); ledger/cap settlement itself is correct. DO NOT fix now; next
  work period with an offline regression (per-step charges vs aggregate usage
  vs allowance), no paid replay, caps never weakened.
- All investigation slots consumed: never create fresh state, reset/restore
  usage, or bypass the cap. No further paid work authorized.
- Persistent demo stays AI-off/running at 127.0.0.1:8080; real state is
  separate (`artifacts/real-meta-smoke/`, ignored).

## 2026-11-01 — T10 corrected smoke PASS (coordinator evidence)

Corrected tracked smoke at `4cff24a` actually PASS 23/0, including both
in-network probes 7/0, backup 0600, isolated restore, retention, cleanup of
own resources only, persistent demo untouched. Log:
`artifacts/reviews/t10-4cff24a-smoke.log`. Coordinator final gates at `4cff24a`:
clean full unit/integration **341 passed, 0 skipped, 15.98s**; Ruff check PASS;
Ruff format PASS (138 files); `uv lock --check` PASS (40 packages). The earlier
conflicting 337 pass predates the 4 helper isolation regressions; the writer's
339 pass + 2 environmental socket skips covers the conflicting env — counts kept
honest, no further broad reruns for this docs-only closeout. UI/E2E hashes
unchanged (15 pass) and the 28-case container matrix remain valid.


## 2026-11-01 — Publication checkpoint preparation

Owner-authorized publication of a separate consolidated snapshot branch;
no merge to `main`, application deployment or additional model calls.
Original development branches and their full history remain local.

- Documentation uses neutral implementation/review terminology. Original
  contribution records, third-party attribution, known product defects and
  historical PASS/FAIL/BLOCKED/NOT RUN evidence remain distinguishable.
- Application source, configuration, assets, tests, scripts and dependency
  manifests are unchanged from the development checkpoint. Existing test
  evidence is reused: 341 unit/integration, 15 E2E, 28 container-browser
  cases and 23 isolated smoke checks. No paid test was repeated.
- Packaging-only change: project and complete bundled-browser license
  texts are retained in the runtime image. Recursive build-context rules
  also exclude local bytecode caches and platform metadata.
- A fresh tracked-export build with four additional synthetic exclusion
  sentinels passed on Linux ARM64. All 145 application/configuration/asset
  files matched the earlier tracked-export smoke image byte-for-byte.
  Image inspection confirmed UID 10001, license texts present and no
  sentinel `.env`, artifacts, bytecode or platform metadata in the image.
- Gitleaks 8.30.1 directory scan was fully redacted: only the already
  reviewed `technical-spec.md:787` cost-heading false positive; exit 1
  retained and no broad allowlist added. Publication history is checked
  separately before the explicit single-branch push.
- Supplied specification SHA-256 remains
  `cdccb82bb874c9cf8578229a4e0cc97047db639e64e306c38fc1b39696c5805e`.
  The existing local demo, private credentials and actual usage ledger
  were not modified by publication preparation.

# T10 local demo/release verification plan — bounded, coordinator approval required

Status: plan only, 31 October 2026, updated with coordinator corrections in `artifacts/reviews/t10-plan-review.md` (1 November 2026). No code, build, container, spend, push, deploy, or submission authorized by this file.
Baseline: clean tree at `33de434` on `feature/t8-meta-adapter`. Canonical workspace only: `/path/to/logcarve`.
Implementation and independent verification are separate stages. Docker checks run in the local verification environment when the coding workspace cannot access its socket; sandbox and approval controls remain enabled. The observed verification environment used Docker 29.8.2 linux/arm64 and Compose 5.5.0.

## Goal

Ship a reviewable T10 slice: reproducible multistage Docker asset build from a fresh tracked export, a protected persistent loopback-only synthetic AI-OFF demo usable on 3 Nov, finite isolated Compose smoke plus offline/restart/backup/restore/client/browser checks, a Settings/DataSources shared-window nav fix with real click tests, honest scale reuse, stale-doc correction preserving history, and English 3-minute demo materials with genuine real-AI gates still NOT RUN.

## Success criteria

- Fresh-clone Docker build reproduces vendored JS/CSS/fonts plus generated template icons and license/provenance texts without host `node_modules`, static caches, `.uv-python`, secrets, `.env`, DBs, logs, or `artifacts/`.
- Persistent demo starts idempotently on loopback only with `AI_ENABLED=false`, synthetic read-only source, non-root, no socket/privileged mode; the documented Nov-3 entry URL shows seeded data (custom window, not the aged-out default 7-day window).
- Random local `SESSION_SECRET`/`HMAC_KEY` generated at demo init, stored only in the protected local demo env, never the product key; product key file never read, no AI enable, no Meta/account/connectivity probe.
- Settings/DataSources roundtrip preserves shared site/source/window/display-zone state; Playwright clicks cover every nav entry and back to a data view.
- Isolated smoke project tears down only its own resources; persistent demo stays usable; source logs byte-identical; replay adds zero rows.
- `artifacts/reviews/scale-summary.md` figures reused verbatim (security derivation ~10.26 s at 1 M, single cold samples, no SLO invented).
- Stale scaffold lines corrected by appending dated entries; no history rewritten; Linux x86-64 stays NOT RUN (ARM64 initial demo labeled as such).
- No public URL, push, `main` merge, Plesk/prod change, submission, purchase, or paid call.

## Approach

Minimal diff on top of `33de434`, in this order: (1) Dockerfile/ignore/licenses, (2) demo Compose profile + idempotent scripts + synthetic seed, (3) nav fix + tests, (4) smoke runner, (5) docs + demo script. Each lands as a reviewable focused commit; coordinator runs every Docker gate and requests fixes.

Key decisions:

- Multistage `Dockerfile`: exact patch pins `node:22.23.4-bookworm-slim` builder (`npm ci` from committed `package-lock.json`, `npm run build` = vendor + js + css + template icons; coordinator verifies tag availability and records architecture) then `python:3.12.16-slim-bookworm` runtime (matching `.python-version` 3.12); copy authored `app/` first, then built `app/web/static/` tree AND generated `app/web/templates/icons/` from the asset stage (`COPY --from=assets`), plus `config/` examples and `requirements.txt`; `USER 10001`, owned `/data`, `HEALTHCHECK` on `/healthz`; Node never ships to runtime. No moving tags; digests may replace pins once coordinator verifies them.
- Ignore/license policy: extend `.dockerignore` with `.uv-python/`, test browsers, `artifacts/`, local keys/env/DB/logs (never `COPY .`). Track license/provenance sources via `.gitignore` exceptions for `app/web/static/vendor/PROVENANCE.md`, `app/web/static/icons/LUCIDE-ISC.txt`, `app/web/static/fonts/INTER-OFL.txt`, `app/web/static/fonts/JETBRAINS-MONO-OFL.txt` so the builder-regenerated texts stay tracked source notices and ship in the final image inside the copied static tree.
- Demo profile: standalone `docker-compose.demo.yml` (no inheritance of the owner base `.env`, no model key/config inheritance); explicit `env_file: artifacts/local-demo-secrets/demo.env` (generated, directory 0700 / files 0600, git-ignored) forcing `AI_ENABLED=false`, empty `MODEL_API_KEY`, `MODEL_DATA_POLICY_VERIFIED=false`, `MODEL_ALLOW_REAL_DATA=false`, verification flags false, no provider probes. `scripts/demo/{init,start,stop,reset,health}.sh` idempotent; `init` creates random local `SESSION_SECRET`/`HMAC_KEY`/admin password only when safely absent and refuses to overwrite existing files; the existing product `MODEL_API_KEY` file is never read or copied. `reset` is nondestructive: verified synthetic reseed of the known 30-row fixture preserving users/tokens/import history/`ai_spend`/smoke counters (or documented idempotent re-import with replay-zero), refuses foreign data, never `down -v` the persistent demo volume, never restores an old usage ledger, never edits source logs.
- Nov-3 window: fixed custom-window entry URL `/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined` covering the full 30-row T8 fixture (Oct 26–28, windows A/B/C), usable on Nov 3; param names verified against `app/web/routes.py::_nav_query`/`_parse_view_params`.
- Nav fix: `_settings_context`/`_sources_context` accept the shared window state and expose `nav_query` (+ canonical back-links) so Settings/Data Sources links carry site/source/window/tz; side-nav already does for data pages. Keep active-view matchers intact. Tests: TestClient roundtrips (runnable in Muse sandbox) plus Playwright click roundtrips through ALL nav entries with selected source + custom window + Europe/Berlin for coordinator execution.
- Smoke: new finite `scripts/smoke_demo.sh` builds from `git archive` of tracked sources only, uses unique project `-p logcarve-smoke-<stamp>`, project-scoped volumes/network (no explicit global `name:` shared with the demo), smoke port distinct from 8080 (default 18080 loopback), refuses pre-existing foreign resources, prints no secrets/tokens/cookies. Asserts public `/healthz`, private login + admin-gated `/readyz` (unauthenticated 401 expected, not health proof), migrations, import + replay-zero, source SHA unchanged, scoped-token client with chat off and unreachable provider, all browser views with local assets only, restart persistence, backup/isolated restore/retention, offline runtime on the isolated internal network. Teardown removes only run-owned IDs/resources.
- Docs: append dated T10 entries to `docs/verification.md`, correct `README.md`/`docs/deployment.md` scaffold lines ("no Dockerfile", "NOT IMPLEMENTED") to point at the implemented state while preserving the original dated rows.

## Steps

1. Dockerfile + ignores + licenses.
   - Files: `Dockerfile`, `.dockerignore`, `.gitignore`, `assets/licenses/*`, `scripts/build_vendor.mjs` (only if a provenance path must change).
   - Bounded commands (coordinator runs): `docker build --no-cache -t logcarve:t10 .`, `docker run --rm logcarve:t10 ls` checks for static tree + notices, `git check-ignore` for `.uv-python`/caches/secrets.
2. Demo profile + scripts + seed.
   - Files: `docker-compose.demo.yml`, `scripts/demo/*`, `config/demo.env.example`, `tests/fixtures/demo/*` (synthetic only), `docs/demo.md` (exact URL, init/start/stop/reset, health, seed anchor, admin login, CLI token + external-client examples).
   - Bounded commands: `./scripts/demo/init.sh`, `./scripts/demo/start.sh`, `curl -sf http://127.0.0.1:8080/healthz`, `curl -sf http://127.0.0.1:8080/readyz` (or implemented readiness path), documented custom-window entry URL opened in browser.
3. Shared-window nav fix + tests.
   - Files: `app/web/routes.py`, affected `app/web/templates/**`, `tests/e2e/test_nav_shared_window.py` (or nearest existing nav file).
   - Bounded commands: `uv run --locked pytest tests/e2e -k nav`, `uv run --locked pytest tests/unit tests/integration`, `uv run --locked ruff check .`, `ruff format --check .`.
4. Smoke runner + offline/restart/backup evidence.
   - Files: `scripts/smoke_demo.sh`, `docs/verification.md` (append-only entry with commit, commands, env, PASS/BLOCKED/NOT RUN, artifact paths).
   - Bounded commands (coordinator): `./scripts/smoke_demo.sh --export-tracked --project logcarve-smoke`, `docker compose -p logcarve-smoke down -v` (smoke only), restart + backup/restore substeps inside the runner.
5. Stale-doc correction + demo materials.
   - Files: `README.md`, `docs/deployment.md`, `docs/verification.md`, `docs/demo-script-3min.md` (English, synthetic stories, startup/recovery, honest limits, real-AI takes marked NOT RUN / allowance-gated).
   - Bounded commands: `python3 -c` link/JSON sanity, `uv run --locked pytest tests/unit tests/integration -q`, redacted `gitleaks dir . --redact=100` + `gitleaks git . --redact=100` (exit-1 retained, reports under `artifacts/reviews/gitleaks-<sha>/`).

## Validation plan

| Gate | Exact check | Expected evidence |
| --- | --- | --- |
| Locked unit/integration, clean + conflicting | `uv run --locked pytest tests/unit tests/integration` and `AI_ENABLED=true LLM_WARN_AT_USD=999 ...` | 321 pass, 0 skip (T8 baseline carried; plus new nav tests, count recorded exactly) |
| Lint/format/lock | `ruff check .`, `ruff format --check .`, `uv lock --check` | Clean |
| Protected E2E | existing 14-test Chromium suite + new nav roundtrips at unchanged UI | Pass, no console errors / external requests |
| Docker build (coordinator) | `docker build --no-cache` from `git archive` export | Reproducible image with icons + notices, no secrets |
| Demo + smoke (coordinator) | demo init/start/health/entry URL; `smoke_demo.sh` full run incl. offline, restart, backup/isolated restore, scoped client, browser views | PASS rows in `verification.md`; failures stay FAIL/BLOCKED, never claimed |
| Secrets scan | redacted Gitleaks dir + history | Only known `technical-spec.md:787` false positive or newly triaged findings |
| Scale | reuse `scale-100000.json` / `scale-1000000.json` | Verbatim import/query figures, security ~10.26 s noted as single sample |

## Risks / open questions

- Custom-window params verified against `_nav_query` (`site, range, from, to, tz, source`) and `_parse_view_params` (`range=custom` needs `from`/`to`, `tz` in UTC/Europe-Berlin); the fixed entry URL above is the implemented value.
- License texts stay tracked via `.gitignore` exceptions (builder regenerates identical bytes); no separate `assets/licenses/` copy, so there is exactly one source per notice.
- Linux x86-64 native remains NOT RUN; ARM64/OrbStack loopback is the labeled initial demo, emulated amd64 (if tried) labeled separately.
- Real-AI demo takes (AI-01/02) stay NOT RUN until the separately approved capped T8 execution; no paid take inside T10.
- None: no owner-file overwrite, source-log mutation, public exposure, push/`main`, Plesk/prod, purchases, key reads, or sandbox/approval weakening — violations block the slice.

## Sources

- https://github.com/docker/docs/blob/main/_vendor/github.com/moby/buildkit/frontend/dockerfile/docs/reference.md (`COPY --from` stage semantics)
- https://github.com/docker/docs/blob/main/content/guides/nodejs.md (`.dockerignore` build-context exclusions)
- https://github.com/docker/docs/blob/main/content/get-started/docker-concepts/building-images/using-the-build-cache.md (`.dockerignore` cache hygiene)
- https://github.com/docker/docs/blob/main/content/guides/python.md (Python `.dockerignore` patterns)
- https://github.com/docker/compose/blob/main/pkg/compose/create.go (loopback `HostIP` port binding stays local)
- https://github.com/docker/compose/blob/main/pkg/e2e/fixtures/volume-test/compose.yaml (named volumes, `:ro` mounts)
- https://github.com/docker/compose/blob/main/pkg/e2e/testdata/TestUpInteractiveWaitsForHealthy/compose.yaml (named volume + `healthcheck` + `depends_on: service_healthy`)

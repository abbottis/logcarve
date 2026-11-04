# Remaining local build plan — testable demo (31 October 2026)

Status: planning only. No application code, dependencies, provider calls,
pushes, deployments or spending are authorized by this plan.
Baseline: clean tree at `3f932e7` on `fix/external-client-findings-route`
(parent `c4a7bc4`, T6 review closure). Scope: single site, one configured
NCSA Combined source; no P1/P2. Target stays Linux x86-64; ARM64/OrbStack
loopback is the initial test/recording environment only.

Authoritative inputs: `docs/mvp.md`, `docs/mvp-implementation-plan.md`,
`docs/acceptance-criteria.md`, `docs/verification.md`, ADR 0002,
`artifacts/plans/demo-readiness-2026-11-03/START-HERE.md`,
`artifacts/client-findings-fix-2026-10-31/HANDOFF.md`, area rules
`app/ai/AGENTS.md`, `app/web/AGENTS.md`, `tests/AGENTS.md`.

## Order and dependencies

T7 (fake-provider assistant) → independent review → T9 part A
(shell/overview) → T9 part B (remaining views) → T10 (Compose
verification, demo prep). T8 preparation runs in parallel with T9;
T8 execution is separately gated and never blocks UI progress.
T9 Ask AI UI consumes the reviewed T7 services; nothing in T9 depends
on real-provider access.

## T7 proposal — bounded assistant, fake providers only (authorize first)

Scope: `app/ai/` consumer of the shared analytics layer only
(providers, typed tools, prompts, evidence serialization kept separate).
Allowlisted read-only tools with server-side validated arguments,
site/time/output limits; fail-closed provider/model/tier validation
(unknown or Contributor handling blocks real-data transmission before
any request); egress gate over prompts, history, tool results, retries
and replay (aggregates, rule refs, windows, sanitized evidence only —
no raw lines, original IPs, query secrets or sensitive context);
timeouts, cancellation, token/step limits, concurrency-aware budget
reservation and accounting under existing tighter limits; usage/cost
records without sensitive content; English local errors with
deterministic API/dashboard intact when chat is unavailable.

Non-goals: no real provider calls, no new dependency without concrete
need, no T9 work, no model-generated SQL, no scope expansion.

Acceptance IDs: AI-03, AI-04, PRIV-01–03, COST-01, COST-02.
Produces no AI-01/02 evidence (fakes cannot satisfy them).

Tests (all with fake providers, synthetic fixtures only): hostile
log-derived URL/UA/Referer inputs incl. prompt/tool-escalation shapes;
captured mock payloads asserting forbidden data absent; tier-change and
replay paths; concurrent budget reservations; cancellation and provider
failure with API/dashboard still usable; existing deterministic
API/client suite rerun proving AI independence.
Commands: `uv run --locked pytest tests/unit tests/integration`,
`uv run --locked ruff check .`, `ruff format --check .`,
`uv lock --check`, redacted Gitleaks of candidate plus history.
Review gate: independent read-only `/review-security` of the exact T7
commit (tool allowlists, authorization, egress, budget concurrency,
failure isolation), findings repaired and reinspected before T9-B.

## Independent review (after T7; repeated after final critical changes)

Freeze candidate; read-only reviewer session at same path; fake
providers only; prioritized findings with file/line evidence. No edits,
commits, provider calls, pushes or release-approval claims.

## T9 — local dashboard, two parts

Part A: local asset build (Tailwind 4 + daisyUI 5 via CSS `@plugin`,
no `tailwind.config.js`; htmx/Chart.js/fonts/icons bundled locally),
login, navigation, filters, Overview. Part B: Security, Crawlers,
Errors, Ask AI, Settings, Data Sources. Both: Jinja2/htmx server
render, central `en` keys, UTC/explicit display timezone, both themes
with persisted override and no wrong-theme flash, CSP-`self` external
scripts, autoescaped log text plus safe model-output policy, server
pagination, empty/partial/error states, `null`/unavailable timing,
coverage and limitation notices, session/CSRF boundaries.
Affected: `app/web/`, `assets/`, `config/locales/`.
Acceptance IDs: UI-01–04, QA-02 (plus AUTH-01 session/CSRF paths).
Tests: repeatable Playwright core paths (pytest plugin, `--base-url`
against loopback, `browser_context_args` for timezone/locale where
needed), desktop/narrow light/dark checks, console/network review with
zero external requests, safe-output and CSRF probes, disabled/failing
AI still usable. New asset/test dependencies pinned with lockfiles at
implementation; Python stays the production runtime.
Current-docs basis (Context7, 31 Oct 2026): Playwright Python pytest
plugin (`/websites/playwright_dev_python`); daisyUI 5 on Tailwind 4
CSS install (`/saadeghi/daisyui`).

## T8 — preparation only

Verify adapter against current official Meta docs; list operator
prerequisites (account/team, credited balance, model access, effective
Standard handling, pricing, protected product `MODEL_API_KEY` distinct
from dev keys); prepare three synthetic investigations with
independently expected analytics. Standing capped proposal once
prerequisites are verified outside the transcript: at most 3
investigations, 12 provider requests incl. retries, USD 1.00 estimated
product cost; tighter existing limits bind. Until then AI-01/02 stay
NOT RUN. No credentials in transcripts, no recording take inside T8.

## T10 — isolated Compose verification and demo prep

Isolated Compose project (OrbStack, loopback only, synthetic data):
fresh non-root install incl. local assets; health/readiness; synthetic
import; authenticated dashboard/client; restart persistence;
backup/restore; deterministic behavior with provider disabled;
reproducible 100k/1M benchmarks (hardware, duration, RAM, DB size);
documented persistent demo profile (seed/reset, exact loopback URL,
setup, start/stop, health checks). Scoped config/doc commits only;
existing `.env` never overwritten blindly. Acceptance IDs: OPS-01–03,
QA-01 (final review), GOV-03 (materials). Keep Linux x86-64 NOT RUN
when executed on ARM64; submission-form fields and Meta account checks
remain owner actions.

## Explicitly unmet gates (carried, not waived)

Linux x86-64 install evidence; AI-01/02 until authorized T8 executes;
publication/production gates; submission requirements behind login.

## Status 2026-10-31 — T7 implemented, frozen for independent review

Candidate `0c08403` on `feature/t7-bounded-assistant` (from `3f932e7`):
bounded assistant on fake providers per the proposal above, including
the review-note corrections (cumulative lifetime budget, conservative
post-dispatch charge, timestamp-safe scrubber, trusted-scope tool
override). Evidence in `docs/verification.md`. Independent
`/review-security` of the exact candidate is the next gate; T9 work has
not started.

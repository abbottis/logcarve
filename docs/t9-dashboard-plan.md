# T9 dashboard plan — local demo build (planning only)

Status: planning only, 2026-10-31. No application/frontend code,
dependencies, provider calls, pushes, deployments or spending are
authorized by this plan. Baseline: clean tree at `4ecc1d3` on
`feature/t7-bounded-assistant`, independently closed per
`artifacts/reviews/t7-4ecc1d3-closure.md` (227 passed, zero skipped;
AI-01/02 NOT RUN; no real transport). Branch for this plan:
`feature/t9-dashboard`.

Authoritative inputs: `docs/mvp.md` (S4), `docs/architecture.md`,
`docs/acceptance-criteria.md` (UI-01–04, QA-02, AUTH-01 session/CSRF
paths), `docs/verification.md`, technical spec v0.4 §2.8/§3/§4.1,
ADR 0001/0002, `docs/remaining-build-plan-2026-10-31.md` (T9 section),
area rules `app/web/AGENTS.md` and `tests/AGENTS.md`,
`docs/development-tools.md`.

Actual implemented-code basis (inspected, not scaffold text):
`app/main.py` composes only the versioned analytics API with admin
session endpoints; no web routes are mounted yet. `app/web/static/`,
`app/web/templates/pages/` and `app/web/templates/partials/` are
empty. `assets/src/css|js`, `assets/fonts/`, `assets/icons/` hold only
`.gitkeep`. `config/locales/en.json` holds 16 starter keys (nav,
no-data/partial-coverage/timing-unavailable, claimed-bot,
investigation-candidate, AI disabled/unavailable/budget, themes).

## Scope

Part A — local asset build, shell, Overview: npm-based local build
(Tailwind 4 + daisyUI 5 via CSS `@plugin`, no `tailwind.config.js`;
bundled htmx, Chart.js 4, Inter Variable + JetBrains Mono WOFF2 with
licenses, bundled SVG icons), Jinja2 base layout with nav, login/logout
over the existing admin session + CSRF, global filters (preset 24h/7d/
30d + custom, explicit display timezone, single-site selector),
Overview (KPI cards, traffic timeline, error distribution, top
referrer/development summaries, findings excerpt, coverage/quality
notices, empty/partial/error states).

Part B — remaining views: Security (scan paths, 401/403/429, client
patterns, findings with rule ID/version + evidence), Crawlers (claimed
families, paths/statuses, crawler 404s), Errors (4xx/5xx groups by
path/status/referer), Ask AI (starter questions populate input only;
send on explicit action; honest disabled/unavailable states, never a
faked answer), Settings/API Access (theme, timezone, language,
retention display; token guidance read-only or CLI), Data Sources
(configured sources, import status/progress/errors, last import).

Both parts: server-rendered Jinja2 + htmx fragments, central `en`
keys, UTC internally, server pagination/sort/filter, both themes with
persisted override and no wrong-theme flash, CSP `self` without
inline/eval, autoescaped log text plus safe model-output policy, no
external browser assets, `null`/unavailable timing (never zero),
claimed-bot and investigation-candidate wording with limitations.

## Non-goals

No real provider transport (Ask AI consumes reviewed T7 services as
is; AI-01/02 stay NOT RUN). No P1/P2 (exports, drill-down, MCP
server, webhooks, multi-site, chart CSV beyond the accessible table).
No second analytics engine: dashboard reads the shared
`app/analytics/service.py` layer, never a duplicated metric path. No
Node production service; no CDN, webfont, icon or tracking requests.
No raw lines, original IPs, query secrets or tokens in HTML, errors
or model payloads.

## Affected files (exact)

- `app/web/routes.py` (new; fragment + page routes over shared
  analytics service), `app/web/` templates under
  `templates/pages/` (login, overview, security, crawlers, errors,
  ask, settings, data-sources) and `templates/partials/` (filter
  bar, KPI cards, paginated tables, chart + data-table, finding
  cards, coverage/quality notices, empty/error states),
  `app/web/static/` (built output only; authored sources stay in
  `assets/`).
- `assets/src/css/app.css` (Tailwind 4 + daisyUI 5 entry),
  `assets/src/js/` (theme override before paint, htmx/Chart.js init,
  timezone display), `assets/fonts/` (WOFF2 + OFL texts),
  `assets/icons/` (bundled SVG subset + provenance).
- `config/locales/en.json` (full UI/error/starter/accessible-label
  coverage; English fallback).
- `app/main.py` (mount web router alongside the API; no analytics
  logic moves into web code).
- `tests/e2e/` (new Playwright core-path suite + synthetic fixtures).
- `docs/` (this plan; verification evidence; README/API’a docs touch
  only if the admin/API-access wording changes).
- Build manifests at implementation: `package.json` +
  `package-lock.json` (assets), `pyproject.toml`/`uv.lock`
  (pytest-playwright dev addition).

## Dependencies (settled 2026-10-31; NOT added this turn)

Settled choices within the delegated scope; all additions land in
part A implementation with pinned versions and lockfiles:

- CSS build: Tailwind CSS v4 standalone CLI via npm (no
  `tailwind.config.js`; daisyUI 5 loaded as a CSS `@plugin`).
  `package.json` + `package-lock.json` committed; built output only
  under `app/web/static/`.
- JS bundles: local pinned **full** distribution bundles of
  `htmx.org` and `chart.js@4` (not CDN, not treeshaken custom
  builds for the demo slice).
- Fonts: Inter Variable + JetBrains Mono Variable WOFF2 served
  locally with `font-display: swap`; OFL license texts committed
  beside the files in `assets/fonts/`. Mono is reserved for IPs,
  hashes, URLs, code, table numerals and technical labels.
- Icons: bundled Lucide SVG subset in `assets/icons/` with license
  verification recorded at implementation; no icon CDN.
- Python runtime (correction: the set does change): **Jinja2 is a
  necessary runtime dependency missing from the current manifest**
  (verified: no `jinja2` in `pyproject.toml`/`uv.lock`, no template
  usage in `app/` yet) and is added in part A with a pinned floor
  plus `uv.lock`. No `python-multipart` in part A: the existing
  login endpoint (`POST /api/v1/admin/login`) accepts a JSON body,
  and the browser login form submits JSON via a small local external
  JS module (CSP-`self` compatible); form parsing is added later
  only if a no-JS fallback form becomes a concrete requirement.
- Python dev: `pytest-playwright` pinned in the dev group with
  `uv.lock`; the matching pinned Playwright browser installs into
  project-local ignored storage (`artifacts/playwright-browsers/`
  via `PLAYWRIGHT_BROWSERS_PATH`, already covered by the
  `/artifacts/` ignore rule) with actual tool and browser versions
  recorded in `verification.md` at implementation.

## View/route design

- `GET /login` serves the browser login form, which submits JSON to
  the existing `POST /api/v1/admin/login` (session + rate limit +
  generic errors) via external JS; `POST /logout` reuses the existing
  admin logout with the per-session CSRF header. No duplicate login
  endpoint was added.
- `GET /` (Overview), `/security`, `/crawlers`, `/errors`, `/ask`,
  `/settings`, `/data-sources`; htmx `GET` fragments for filter
  changes, pagination, sorting and chart refreshes with safe
  filter-URL state (no secrets in URLs).
- Every data view passes `AnalyticsFilter` + exact `TimeWindow`
  server-side; API Bearer [REDACTED] authorize nothing in the browser and
  browser sessions authorize nothing in `/api/v1`.
- Ask AI posts only to the existing `POST /api/v1/chat/ask` with
  session + CSRF; `ai.disabled` (no key / chat off),
  `ai.unavailable` (failure/timeout/budget) and `ai.budget_reached`
  render as honest states with deterministic views intact. Model
  answers render as **escaped plain text**; evidence travels as
  separate server-generated links (tool, filters, result/snapshot
  ID, observed time) that open the underlying data view. No markdown
  rendering, no raw HTML from the model.
- Token administration stays CLI-based (existing `auth` CLI; token
  shown once). Settings/API Access shows read-only guidance: API
  base address, OpenAPI link, scopes, external-LLM data-responsibility
  notice. No browser token issuance in the demo slice.
- Data Sources shows configured source IDs, import status/progress/
  errors and last-import date plus the documented existing admin CLI
  commands. No new source-path input and no log-upload API: the
  browser never supplies filesystem paths.

## Screen design (settled 2026-10-31; taste review applied)

Target: a calm, dense analytics workspace. No decorative hero, no
marketing headline, no extra branding work. Corrections applied from
the taste pass: spec-mandated sky/slate tokens only (no purple/indigo
accents, no gradients); one clear page title per view (no eyebrow
pill + headline + CTA hero); KPI cards vary in emphasis by content
rather than repeating an identical icon-grid; a single daisyUI radius
scale throughout (no `rounded-2xl` everywhere, no glassmorphism, no
hover-lift); Inter for UI text with JetBrains Mono reserved for
technical values; body text at spec muted tones, never gray-400/500;
Lucide SVG icons only, no emoji; motion limited to theme-safe
transitions that honor `prefers-reduced-motion`; data never encoded
by red/green alone (labels + counts accompany every status color).

App shell (all views): a persistent compact left navigation (icons +
labels; collapses to an icon rail, then a top bar with a menu button
on narrow viewports) with the six MVP entries plus Settings and Data
Sources; a slim top bar holding the site selector (single entry for
the MVP), the display-timezone indicator, the theme toggle
(system/light/dark, persisted override applied before paint) and
logout. Below it, one global filter bar: preset range (24h / 7d /
30d / custom from-to), applied uniformly to every view, with filter
state kept in safe URL query parameters.

Hierarchy within a view: page title with the observation window and
coverage note beside it; KPI cards in a single row (total requests,
error share, claimed-bot share, top-status count); one traffic
timeline (line) and one status distribution (stacked bar), each
immediately followed by its accessible data table rather than a
chart-only presentation; then the view-specific paginated tables and
finding cards. Source-coverage and quality warnings sit directly
under the filter bar wherever imports are incomplete or failed, and
the timing-unavailable notice replaces any latency panel for
Combined-only sources (missing timing is `null`, never zero).

- Overview: KPI row, traffic timeline + table, error distribution +
  table, top-referrer and development/endpoint summaries, security
  finding excerpts with rule IDs linking to the Security view.
- Security: scan-path table with rule ID/version, 401/403/429
  breakdown, repeated-client-error patterns, investigation-candidate
  cards each carrying evidence filters, window, counts and
  limitations.
- Crawlers: claimed-family table over time, top crawled paths,
  crawler 404s with referrers, robots/sitemap requests; every bot
  label reads "claimed", never verified.
- Errors: 4xx/5xx groups by path, status and referer host with
  server pagination and stable sort; empty state when the window is
  clean.
- Ask AI: category-grouped starter-question buttons that only fill
  the input; explicit send; answer in escaped plain text with
  server-generated evidence links; disabled/unavailable/budget
  states keep the rest of the dashboard usable.
- Settings: read-only theme/timezone/language/retention display
  plus API-access guidance. Data Sources: source table (ID, server
  type, format, enabled), import history (fingerprint prefix,
  accepted/rejected counts, status, error summary) and the admin CLI
  commands for import, retention, backup and restore.

Narrow layouts: nav collapses as above; KPI cards stack two-up, then
one-up; tables scroll horizontally inside their container with sticky
first columns; charts keep a minimum readable height and their data
tables remain the primary content for screen readers. Keyboard path:
visible focus on every control, skip link to main content, logical
tab order through filter bar before tables, chart canvases labelled
with text alternatives pointing at their tables.

Light/dark: spec §3.4 token table only (page slate-50/950, surface
white/900, border 200/800, text 900/100, muted 600/400, accent
sky-600/400, success emerald, warning amber, danger red). The
persisted override is read by an inline-free external script placed
to run before first paint; system preference is the default.

## Validation (repeatable, recorded in verification.md)

- `uv run --locked pytest tests/unit tests/integration` (clean +
  conflicting synthetic env) and `ruff check .` /
  `ruff format --check .`, `uv lock --check`, redacted Gitleaks of
  candidate plus history.
- New `tests/e2e/` Playwright suite (project plugin, `--base-url`
  against loopback, `browser_context_args` for timezone/locale):
  login/logout + CSRF probe; all six views reachable via nav;
  global filters change every view; paginated/sorted tables;
  charts each paired with an accessible data table; empty, partial
  (failed-import warning), error (503/validation envelope) and
  zero-external-request network review; console error-free;
  desktop + narrow viewports in light and dark; system/manual theme
  persistence with no wrong-theme flash; keyboard-only pass with
  visible focus; timing-unavailable notice with no fabricated
  percentile; claimed-bot/investigation wording present; Ask AI
  disabled and failing-provider runs show honest states and send
  nothing fake; analytics-token negatives unchanged (API-04).
- Screenshots (desktop/mobile × light/dark) complement the suite
  per QA-02; a Muse task completion is not test evidence.
- Acceptance mapping: UI-01 (locale catalog + UTC/display-tz),
  UI-02 (nav/login/filters/tables/charts), UI-03 (themes/keyboard/
  responsive), UI-04 (self-hosted assets + CSP evidence), QA-02
  (visual QA), AUTH-01 (session/CSRF paths), ANA-02/ANA-03
  presentation guarantees.

## Settled in this review (2026-10-31)

1. Asset pipeline: Tailwind CLI; full pinned Chart.js/htmx bundles.
2. Token management: CLI-based, read-only Settings/API guidance.
3. Data Sources: status display + documented admin CLI; no new
   path input or upload API.
4. Model output: escaped plain text + server-generated evidence
   links; theme override via external pre-paint script, no inline.
5. Playwright: pinned browser in `artifacts/playwright-browsers/`,
   versions recorded at implementation.

## Remaining real blockers (not waived)

- Linux x86-64 install evidence (ARM64/OrbStack loopback is the
  demo/test environment only).
- AI-01/02 until the separately gated, authorized T8 capped run
  executes; Ask AI ships honestly disabled until then.
- Benchmark hardware declaration and 100k/1M measurements (T10).
- Independent review of the T9 implementation before any release
  step (QA-01); publication/production gates stay owner-authorized.

Next gate: coordinator approval of part A. Implementation (T9-A
first) starts only on explicit owner authorization, one part at a
time, with no application/frontend files or dependency installs in
this planning turn.

# Owner UX review plan — 2026-11-01

Date: 2026-11-01. Reason: owner reviewed screenshots/layout of the
acceptance-readiness checkout on the public source branch and supplied
ten sanitized layout/wording items (real addresses withheld; no owner
Desktop or screenshots inspected). This plan records the settled
practical interpretation, splits the work into Stage A (this task) and
Stage B (next task), and maps each item to files, acceptance IDs,
tests and non-goals.

Authorization: current user turn authorizes bounded implementation via
Muse Spark 1.3 Contributor/medium as sole writer on standalone
public-source/synthetic workspace `feature/owner-ux-review-2026-11-01`.
Supersedes prior STOP only for the bounded Stage A scope below. No
product/provider calls, purchases, GitHub push, main merge, production
deployment, broad dependencies, rule/code imports, private-history
access, or real-allowance changes.

## Stage A (implement now)

A1. Drop repeated "Claimed" prefix from named-bot dropdown/table/
display names (presentation layer only). One clear limitation note per
relevant page/help ("Identified from User-Agent; identity not
verified"). Preserve API/machine IDs, rule definitions/versions/
provenance, AI cautious meanings; never imply verified bots. Generic UI
may say "Bot traffic"/"Bots" with legend; no blind substring
replacement in paths/UA/data.
Files: `app/web/routes.py` (display-title helper), filter/crawler/
overview templates, `config/locales/en.json`.
IDs: ANA-03, UI-01.

A2. All 599 image zone options carry signed UTC difference after the
readable name (e.g. `Europe/Berlin — UTC+01:00`, `Kathmandu — UTC+05:45`,
`St. John's — UTC-03:30`). Offset is calculated for the APPLIED UTC
window start (not review date), labelled with reference + DST caveat.
UTC storage/input window/sort values/URL unchanged. Offset notice
updates only on successful Apply/OOB; no stale default/settings text.
Cache ZoneInfo objects (bounded); never reopen 599 zone files per
request. Sign/fractional/Etc/GMT-reverse/DST test dates and malformed
zones handled. Exact HH:MM, seconds only for historical sub-minute
offsets. Catalog order/default (server default, UTC, region/city)
unchanged.
Files: `app/web/timezones.py`, `app/web/routes.py`, filter bar.
IDs: UI-01, UI-02.

A3. Human-friendly capitalized display names without underscores in
headings, dropdown labels, active-filter summaries, group tables/charts
and display enums: central `en` locale mapping for AI crawlers, Search
crawlers, SEO tools, Automation tools, etc.; proper provider/product
capitalization; unclaimed → "Unspecified" as display label only. API
fields/IDs, original data paths/agents/pseudonyms and canonical
timezone values stay EXACT. No data mutation.
Files: `config/locales/en.json`, templates, `app/web/routes.py`.
IDs: ANA-03, UI-01.

A4. "User generated" is not separately measurable from Combined logs.
Keep 4 exclusive classes with consistent counts; explain Browser-like
as potential user traffic, not proof of people/sessions. A helpful
explicitly equivalent quick view is acceptable; no fifth bucket or
human-verified metric.
Files: locale strings, Overview legend, quick-view link (A8).
IDs: ANA-01, ANA-04.

A5. Stage B only (NOT in A): deterministic "Conflicting bot identities"
Security candidate (not proven fake) using unambiguous exclusive
named-provider UA tokens. Never call ordinary Mozilla+Googlebot fake or
same-provider variants conflicting. All-row totals exact, no first-5k
UA sampling, no silent bot removal, explicit Help limitation.
Deferred to Stage B task after the Stage A commit.

A6. Method and Exact status become native dropdowns: All option,
standard methods/status phrases plus observed/custom CURRENT selected
values retained. Preserve unusual valid methods/statuses supported by
API; no breaking API validation changes. Data-derived option queries
parameterized/scoped/bounded, no N+1, safe HTML. Standard
`http.HTTPStatus.phrase` labels known statuses, generic labels for
valid 100–599 unknowns. No raw text inputs for these two controls.
Files: `app/analytics/queries.py` (distinct methods/statuses),
`app/web/routes.py`, filter template.
IDs: ANA-05, API-05, UI-02, UI-05.

A7. Ask AI starter "Help me create firewall rules" as MANUAL-REVIEW
guidance/draft only. Starter populates without sending. Prompt asks for
operator platform/requirements, uses bounded existing security
evidence, never invents original IPs from HMACs, never applies/
executes firewall changes, never adds HTTP/shell/tools. Placeholder-
based review suggestions only; no deployable-rules promise. Product
stays AI-off; all existing read-only/egress/server caps kept.
Files: `config/locales/en.json`, `app/web/routes.py` starter count.
IDs: AI-01, AI-03.

A8. Internal authenticated Help page + sidebar link: usage and API
guidance (filters/window/UTC offsets/labels/traffic meaning, bot
identity limits, privacy/pseudonyms/GeoIP-unavailable, explorer/
details/sorts incl. Stage B notice, troubleshooting/empty states, API
token vs admin session distinction, server pagination/scope/UTC
contract, safe curl/stdlib examples with placeholders, no real
token/key). Works with chat off, entirely local assets, no auto
external requests. Sessions required; bearer tokens cannot open UI.
Preserves active filter navigation.
Files: new `app/web/templates/pages/help.html`, routes, base sidebar,
locale keys.
IDs: UI-01, UI-02, API-01.

A9. Full screenshot-like sortable log overview is Stage B (next task,
not here): transform Requests page to 8 usable columns + expandable
per-row minimized details, allowlisted server sort headers, stable
tie-breaks, no raw-IP/country claims. No new log upload/import UX or
source mutation. Auth/site/source/time/privacy bounds, pagination and
existing newest/oldest API sorts kept.
Deferred to Stage B task after the Stage A commit.

A10. Stage A fixes Crawlers 3-table crunch + ordinary-name word
breaking: full-width stacked groups (or demonstrably readable layout),
no mid-word breaks of ordinary names; narrow viewports
contained/accessible; usable at 1440/1024/768/390 both themes; page
overflow not hidden to conceal layout bugs; tables may scroll
internally at narrow widths; ordinary names must not letter-wrap.
Browser assertions on actual name-cell widths/nowrap + content fit.
Files: crawlers template (+ small authored CSS if needed, rebuilt
locally).
IDs: UI-02, UI-03.

A11. Small useful quick views now: compact links for 404 issues, 5xx,
bot traffic, potential user traffic, largest responses (B sort).
Preserve selected site/source/window; matcher replacement/reset paging
explicit; contradictions rejected; no silent scope widening. Small
number backed by existing metrics; status phrases + readable known
byte sizes as table polish; no conversion/session/indexing/training/
GeoIP/person claims, no unbounded new subsystem.
Files: Overview template (+ routes context), locale keys.
IDs: UI-02, UI-05, ANA-05.

## Stage B (separately handed over after the Stage A commit)

- B1 (item 9): 8-column Requests overview + expandable per-row details,
  allowlisted sorts, stable tie-breaks.
- B2 (item 5): "Conflicting bot identities" Security candidate with
  unambiguous exclusive named-provider tokens, totals exact, Help
  limitation.
- Not claimed implemented in Stage A; reported as deferred below.

## Conditional decisions (truthful)

- C1. Presentation-only label changes (A1/A3): bot rule YAML, API
  fields, rule IDs/versions/provenance and stored data are untouched.
  "Claimed X" → "X" and underscore → spaced labels happen in a display
  helper + locale map. If a consumer needs the literal claim wording,
  the rule title/meaning remain available via the API and detail panel.
- C2. Timezone offsets (A2): reference instant is the applied window
  `time_from` (UTC). DST transitions inside the window are noted as a
  caveat, not per-row offsets; stored/sorted values stay UTC.
- C3. Method/status dropdowns (A6): parsing/validation unchanged
  (unusual-but-valid values still accepted via URL/API). Dropdown
  options = standard set + observed values in current scope; a current
  selected value outside both is retained as an extra option.
- C4. Quick views (A11): implemented as explicit preset links reusing
  existing pages/filters (no new endpoints, no new metrics). "Largest
  responses" reuses the existing Overview paths `bytes_desc` sort.
- C5. Help page (A8): session-only like other data pages; bearer
  tokens redirect to login. No external links except the owner-supplied
  Google verification reference (item context) as an optional
  documentation link with no automatic network use.
- C6. No schema/data migration; 120-row immutable fixtures, demo
  seeder, digests and real-data allowance untouched.

## Files touched (Stage A)

- `docs/owner-ux-review-plan.md` (this plan)
- `config/locales/en.json` (display labels, Help, starter 9, legends)
- `app/web/timezones.py` (cached offset labels at window start)
- `app/web/routes.py` (display helpers, method/status options, Help
  route, starter count, quick-view context)
- `app/analytics/queries.py` (scoped distinct methods/statuses)
- `app/web/templates/partials/filter_bar.html`
- `app/web/templates/partials/crawlers_content.html`
- `app/web/templates/partials/overview_content.html`
- `app/web/templates/partials/active_matchers.html`
- `app/web/templates/pages/help.html` (new)
- `app/web/templates/base.html` (Help nav)
- `app/web/templates/pages/ask.html` (starter count is server-driven;
  template unchanged expected)
- `assets/src/css/*` + rebuilt `app/web/static/app.css` only if a new
  class is needed (no Tailwind auto-scan noise committed)
- `tests/unit/test_owner_ux_stage_a.py` (new), web integration
  additions, Playwright maintenance additions
- `docs/verification.md` (actual Stage A evidence)

## Tests

- Unit: label/data separation, full-catalog offsets at controlled
  dates (DST/fractions/Etc-GMT/sub-minute), cache/default/explicit/
  OOB/failed-Apply behavior, HTTPStatus phrases + unknown fallback.
- Integration: dropdown standard+observed+custom retention, empty
  data, session-gated Help with safe examples/links, starter
  populate-only (no dispatch), filter state across Help and quick
  views, contradiction rejection.
- Playwright (maintained, `chromium_sandbox=True`): filters/offset
  change, readable Crawlers names, Help, both themes, mobile widths.
  Coordinator runs actual browser/Docker later; do not weaken controls
  or retry known sandbox denials.
- Commands: locked `uv run pytest <focused>`, `ruff check`, `ruff
  format --check`; local asset build only if CSS changed.

## Dependencies / non-goals

- No new dependencies, schema/data migration, fixture changes, digest
  changes, or product/provider calls. No Stage B analytics (explorer
  sorting/details, bot-identity signal). No upload/import UX, no
  firewall execution, no GeoIP, no fifth traffic bucket.

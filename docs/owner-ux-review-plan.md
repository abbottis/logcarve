# Owner UX review plan — 2026-11-01 (closed: independently verified, owner acceptance pending)

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

## Stage B status — 2026-11-01 (implemented on `feature/owner-ux-review-2026-11-01`)

Bounded implementation, same sole-writer public/synthetic checkout,
exact model `muse-spark-1.3-contributor`/medium, sandbox/approval ON,
no agents/calls/push/main merge/production. Synthetic fixtures only;
no schema migration, 120-row fixtures/digests/seeds untouched.

- B1 done: Requests is an 8-column log overview (Client compact HMAC,
  Access, Time in selected zone with UTC retained, Method badge, Path,
  Status badge+phrase, Size with explicit units/`unavailable`, Details
  action) with expandable per-row panels (200-char UA sample with
  honest truncation note, referrer host, traffic/bot/category/provider/
  purpose metadata, full HMAC, UTC+local timestamps with offset, rule
  ID/version, unavailable-timing note; never raw lines, IPs, query
  values or countries). Server sorts for Client/Time/Method/Path/
  Status/Size ascending+descending with aria-sort, visible direction
  and timestamp/id tie-breaks; legacy `newest`/`oldest` kept stable;
  Action unsortable. Details use native buttons + delegated external
  `assets/src/js/requests.js` (CSP `self`, no inline/eval), keyboard
  accessible, working after htmx Apply/paging; narrow viewports scroll
  inside the contained table.
- B2 done: `sec-conflicting-bot-identity` v1 (new category
  `conflicting_bot_identity`; security ruleset v1→v2, old rules/
  versions untouched, bot catalog stays 77 rules with unchanged
  first-match order) fires only for unambiguous named tokens of two
  or more distinct providers from an explicit 9-token known set
  (`app/analytics/conflict.py`: URL-stripped token-boundary matching;
  Mozilla/generic/curl/monitoring/`notgooglebot`/docs-URL/same-provider
  negatives). Shared pure cached detection backs a SQLite UDF
  (`conflicting_bot`), all-row exact SQL aggregation (no 5k cap, no
  full-table Python rows, no N+1) with bounded explicitly-labelled
  samples; the candidate rides the deterministic `security_findings`
  path so the dashboard, API `/security/findings` and assistant tools
  see identical counts/rule-version/limitations, and rows show a
  potential-identity signal computed from the full stored UA (never
  exposing it). Help documents the candidate plus the primary Google
  verification reference; unknown agents stay unknown, absence of the
  candidate proves nothing, no removal from counts, no auto-block.
- B3 done: "Largest responses" sorts individual Requests by
  `bytes_desc` (metric exact); status phrases and known-byte formats in
  the Requests table; quick views keep site/source/window with explicit
  matcher replacement and paging reset.
- Stage A coordinator findings fixed in the same checkout: ZoneInfo
  cache 128→1024 (two full catalogue renders share every zone, proven
  by miss-count test); successful Apply refreshes the timezone/method/
  status option labels out-of-band alongside the notice (exactly one of
  each DOM id per response); Edge/Opera browser markers precede generic
  Chrome; Crawlers groups note covers bots AND automation; e2e file
  renamed to a unique basename; identity legend asserted as semantic
  visible text.
- Evidence: new `tests/unit/test_conflict_detection.py` (10),
  `tests/integration/test_owner_ux_stage_b.py` (sorts/paging/API-vs-
  service/hostile sorts/cross-site/source/privacy/conflict exactness/
  5100-agent counts/samples/projection/browser regression/web columns/
  details/OOB/quick-link/API agreement), updated maintained tests
  (`test_web_slice_b2`, `test_traffic_api`, `test_rules`,
  `test_owner_ux_stage_a`, renamed e2e with new sort/details browser
  coverage). See `verification.md` for actuals.

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

## 2026-11-01 closeout — independently verified, owner acceptance pending (docs-only)

Stage A+B complete on public `feature/owner-ux-review-2026-11-01` at
HEAD `f0182fb` (application anchor `ffaf737`; later commits tests/docs
only). Runtime image built from `a087c3e`; no fresh build claimed for
later commits. Independent evidence in `docs/verification.md`: 536
unit/integration, 29 E2E, 78+53 API checks, 121 offline mock checks,
Ruff/lock/diff, 8/0 candidate + 24/0 offline Compose, 36+8+12 browser
checks on built candidate AND updated live 8080, redacted Gitleaks
(only known `technical-spec.md:787` false positive). Earlier E2E
19/9, 27/2, 28/1 FAILs preserved as stale-test history. Changed-path
review found no unresolved high/medium defect in this slice; NOT
whole-project QA-01/release approval. Real AI stays 2-of-3 INCOMPLETE,
x86-64 NOT RUN, demo AI-off, no new paid calls, no allowance reset.
Live 8080 updated with the exact tested image (backup + rollback kept;
120 rows, schema 4, credentials unchanged); loopback bridge demo is not
air-gapped — offline proof is the separate internal-network run.
Owner can review today: Requests/Crawlers/Help, filter state, timezone
labels, Security candidate and the Ask starter. Honest semantics kept:
no fifth "user generated" class (Browser-like quick view is explanatory,
same bucket); conflicts are investigation leads only. Changed
requirements recorded 2026-11-01 against ANA-01/03/04/05, UI-01/02/03/05,
API-01/05, AI-01/03 (see verification entry).

## 2026-11-01 addendum — Stage B3bcb915 browser-test maintenance (test-only)

Date: 2026-11-01. Reason: the coordinator's protected-Chromium diagnostic at
Stage B `3bcb915` (28 tests: 19 PASS / 9 FAIL, recorded in
`artifacts/task-inputs/owner-ux-b-review.md`) enumerated 9 stale/unstable
maintained-test expectations against the actual UI. This bounded correction
updates only `tests/e2e/test_dashboard.py`, `tests/e2e/test_slice_b.py`,
`tests/e2e/test_timezone_select.py` and `tests/e2e/test_owner_ux_browser.py`
(no app/config/asset/fixture change; no confirmed application defect found):
named Main navigation (Quick views is a second nav), numeric+phrase status
agreement via parsed `200 · OK` codes, 9 starters with the Security
MANUAL-REVIEW prompt kept input-only, native `#f-status` select value, stable
aria-controls detail binding, actual 8-column + expanded-details explorer with
Time-header sort semantics, Time-column JST, and a new winter→summer
Europe/Berlin option-label (UTC+01:00→UTC+02:00) Apply test. Evidence:
`docs/verification.md` entry of the same date; browser execution stays
coordinator-owned.

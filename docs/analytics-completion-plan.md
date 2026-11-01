# Analytics completion plan — traffic analysis, rich charts, bot drilldown

Status: **DELIVERED and independently verified — 2026-11-01, closeout.**
ANA-04/ANA-05 accepted; API-05 and UI-05 added to
[acceptance criteria](acceptance-criteria.md). No application changes in this
document. Slices A, B and C were implemented on
`feature/traffic-analytics` and verified by the independent local runner
(see `docs/verification.md`); implementation plus independent AI-assisted
planning, review and testing produced the result, with no exclusive
single-tool or manual-only authorship claim.

Owner request: complete fundamental log analysis, LogWerk-style traffic
selection and named-bot sorting, then implement and test. References:
workspace task inputs (ignored `artifacts/task-inputs/`: traffic-analysis
scope, LogWerk reference, independent plan/early/scope reviews), public
[LogWerk repository](https://github.com/abbottis/logwerk) and
[GoAccess features](https://goaccess.io/), plus spec §2.6/2.7/2.8/3.3.

## Session coding mode (owner-authorized)

Exact effective coding model `muse-spark-1.3-contributor`, medium effort,
Contributor ON for public source + synthetic fixtures only. That supersedes
the old Contributor-off coding default for that data only. Unchanged:
sandbox + approval review stay on, one lead / no agents, no real logs, no
real product/provider calls, no push/main/public deployment. Product
Standard/egress controls remain fail-closed and separate from the coding
session's Contributor mode. Recorded in [guidance](muse-code.md) and the
dated `AGENTS.md` exception.

## 1. Gap matrix: LogCarve current vs LogWerk vs GoAccess

Legend: ✅ verified present · ❌ verified absent · ◐ partial · ❓ unverified
capability claim (not relied upon). GoAccess panel listings below are
capability claims from its public feature pages, not proof of equivalent
global filters. No LogWerk parity is claimed.

| Capability | LogCarve now | LogWerk (MIT, pinned) | GoAccess | Plan verdict |
| --- | --- | --- | --- | --- |
| Traffic selection (all / browser-like / bots / automation / unknown) | ❌ filter has method/status/path/referer only | ✅ traffic-type selection | ❓ panels imply views, no equivalent filter proven | **In scope (Slice A)** |
| Named-bot + category selection | ❌ 5 rules, no named filter | ✅ named bots, categories | ❓ hosts/UAs listed | **In scope (Slice A)** |
| Provider/purpose grouping | ❌ | ✅ provider + purpose/type | ❌ | **In scope, configured claims only (Slice A)** |
| UA rule catalog breadth | ❌ 5 rules | ✅ 75 named patterns | ❓ built-in list | **75 adapted + 2 original (monitoring/fallback), Slice A** |
| Requests/errors/bytes timelines | ◐ basic timeseries, no bytes | ✅ | ✅ | **In scope (A backend, B panels)** |
| Status breakdown | ◐ status distribution query | ✅ | ✅ | **In scope (A backend, B panels)** |
| Traffic/bot shares | ❌ | ✅ | ✅ | **In scope (A backend, B panels)** |
| Paths by hits/errors/bytes | ◐ hits/errors, no bytes | ✅ | ✅ | **In scope (A backend, B panels)** |
| Referrers + target paths | ◐ top referrers | ✅ | ✅ | **In scope (A backend, B panels)** |
| Path-based resource kinds | ❌ | ✅ | ✅ | **In scope (A backend, B panels)** |
| Claimed browser/OS distributions | ❌ | ✅ | ✅ | **In scope, claim-labeled (A backend, B panels)** |
| Weekday/hour heatmap | ❌ | ✅ | ✅ time panels | **In scope (A backend, B panels)** |
| Pseudonymized client aggregates | ❌ | ✅ hosts | ✅ | **In scope, HMAC-only (A backend, B panels)** |
| Bot drilldown (paths/404s/robots/sitemap, sorting, paging) | ◐ per-family details only | ✅ sortable exploration | ◐ | **In scope (A backend, B panels)** |
| Sanitized paginated request explorer | ❌ | ✅ request-level view | ✅ | **In scope (A backend, B panels)** |
| Missing timing as unavailable | ✅ `available: false` | n/a | n/a | **Preserve (ANA-02)** |
| Parsed HTTP version persisted | ❌ parser reads it, storage has no column | n/a | n/a | **Explicitly unavailable; additive column only with separate justification (deferred)** |
| GeoIP / protocol / timing invention | ❌ correctly absent | has GeoIP | has GeoIP | **Non-goal: no invented geo/timing/protocol/session metrics** |
| gzip/custom formats/rotation | ❌ | ❓ gzip/custom noted as LogWerk-side features | ✅ format range | **Deferred, recorded only** |
| Export/import UX, aggregated CSV/JSON reports | ◐ partial CSV/table alternatives | ❓ export UX present | ❓ | **Deferred to Slice B/C decision; no parity claim** |
| Session reconstruction, live tail, raw-IP views | ❌ | session/person inference present | live/GeoIP | **Non-goal: never copy session/person inference** |
| MCP server, webhooks | ❌ P1 | n/a | n/a | **P1, unchanged** |

## 2. Classification and filter contract (shared by all consumers)

New `AnalyticsFilter` fields (all optional, allowlisted, server-validated):

- `traffic: all | browser_like | claimed_bot | other_automation | unknown`
- `bot` (named rule id), `category`, `provider`, `purpose` (validated against
  the loaded versioned ruleset; unknown values reject, never widen)
- `status_class: 2xx | 3xx | 4xx | 5xx` alongside exact `status`;
  contradictory `status` + `status_class` rejects safely
- `search`: bounded (≤128 chars) LIKE-escaped substring over the stored
  sanitized path, user agent, minimized referrer host and client
  pseudonym (query values are already discarded at import; method/status
  keep their separate controls). Shared consistently by the dashboard/API
  explorer and the aggregate tool selectors; never a raw-row tool.
- Sorts are query-specific allowlisted literals with stable ties:
  paths `requests_desc | errors_desc | bytes_desc`; bots
  `requests_desc | name_asc | category_asc | errors_desc | bytes_desc`;
  explorer `newest | oldest`. Filter changes reset offsets (enforced in
  Slice B URL state; API callers receive validation, not silent correction).

Semantics:

- Every mandatory category covered: `search_crawler`, `ai_crawler`,
  `seo_tool`, `monitoring`, `generic_bot`, `suspected_automation`, `unknown`;
  plus `social_bot`, `federation_crawler`, `feed_fetcher`, `automation_tool`.
- Remap (documented, review-accepted): CLI/HTTP clients, headless browsers
  and security scanners → `automation_tool`; search-engine media/preview/ads/
  audit fetchers → `search_crawler`; generic crawlers, archivers, plagiarism
  checkers → `generic_bot`; social → `social_bot`; federation →
  `federation_crawler`; feeds → `feed_fetcher`. Provider/purpose are
  configured claims, never proof of training use, indexing or verified identity.
- Catalog v3 holds 77 entries: 75 file-ordered named rules (70 adapted from
  LogWerk, 5 pre-existing LogCarve IDs kept) plus 2 original LogCarve rules
  closing the file: `bot-mon-uptimerobot` (`monitoring`, documented
  upstream UA `UptimeRobot`) and `bot-suspected-generic`
  (`suspected_automation`, `bot|crawl|spider|scrap|scan` signals) ordered
  after every named rule, so named claims always win and generic signals
  are suspected automation, never proven crawler or human.
- Traffic mapping: crawler/social/federation/feed/generic categories →
  `claimed_bot`; `monitoring`/`automation_tool`/`suspected_automation` →
  `other_automation`; no match + browser marker → `browser_like`; anything
  else (including NULL UA) → `unknown`. An unmatched UA is never
  automatically browser-like.
- Precedence: file order = match order, specific-before-generic
  (e.g. `googlebot-image` before `googlebot`); `n8n` keeps word boundaries;
  every `ua_contains` fragment is regex-escaped. No client-supplied
  regex/SQL anywhere: patterns come only from the versioned admin rule file
  and travel as bound parameters.
- Rule provenance: `config/bot_rules.yaml` v2 → v3, each rule carries
  id/version/category/provider/purpose/meaning; responses echo
  `classification_rule_id`, `rule_version`, filters, coverage, warnings.
- Detail safety: `bot_detail` never overrides an active named-bot filter
  with the path rule id — path/filter conflicts reject (400), disjoint
  but valid selections return explicitly empty (404, no rows in scope).
- Heatmap honesty: `dst_merges` counts local DATE+hour collisions only
  (genuine fall-back overlap), never ordinary weekly repetition;
  fractional-offset display zones reject unless every bucket offset in the
  window is exact.
- SQL design (concrete): one registered SQLite scalar
  `classify_ua(user_agent, spec)` evaluating ordered predicates in file
  order with early exit (a single combined alternation would prefer the
  earliest text position over file priority, e.g. `Mozilla` at 0 hiding a
  later `GPTBot`). One Python call per row, never one call per rule per
  row; a bounded per-UA cache keeps repeats O(1). The spec string is
  server-generated from the versioned rule file (escaped literals plus
  file-validated `ua_regex`, e.g. `\bn8n\b`) and travels as a bound
  parameter. Base site/time/source filters apply first; classification is
  a pure read-time expression over `user_agent` (NULL → unknown, legacy
  `bot_family` columns untouched, no write-on-read). Every row yields
  exactly one traffic class; bucket totals sum exactly. The old bounded
  distinct-UA scan is removed; evidence samples stay bounded and
  explicitly counted. A Python mirror implements the identical rule order,
  with SQL-vs-Python agreement over every fixture UA plus
  priority/boundary vectors (`Mozilla/5.0 GPTBot/1.0`, lower-priority
  token textually first). 100k-row classification benchmarks at ~0.06s
  isolated (not app scale); no redesign, no SLO.

## 3. Query and performance strategy (read-only)

- One analytics layer (`app/analytics/`): dashboard, `/api/v1` and internal
  Meta tools share contracts + queries + services. No browser-side
  secondary classifier.
- Fixed parameterized SQL only; sort orders from allowlist literals.
  Classification filters reuse the same `classify_ua` expression, so
  filtering happens in the database — never by loading full request
  datasets into Python or the browser.
- Server-side pagination for all large tables; explicit truncation flags stay.
- Legacy DB compatibility: nullable columns stay nullable; old databases
  query unchanged.
- Slice A endpoints (all token site/source enforced, bounded search/output,
  coverage metadata): extended `summary`, `traffic/timeseries` (+bytes),
  new `traffic/breakdown`, `traffic/resources`, `traffic/browsers`,
  `traffic/heatmap`, `traffic/clients`, extended `paths` (+bytes/sort),
  `referrers`, `errors`, `crawlers` (exact per-rule counts, same Finding
  shape), new `bots` table, `bots/{rule_id}` detail, `requests` explorer,
  unchanged `security/findings`, `performance`. Explorer rows expose only
  time/method/path/status/bytes/minimized referrer/UA≤200 chars/pseudonym/
  traffic/rule — no raw lines, original IPs or query values.
- Measurement, not SLO: representative filtered queries (traffic × bot ×
  window) against the 100k synthetic benchmark DB; record hardware, elapsed,
  rows scanned, DB size (OPS-03).

## 4. Trusted filter propagation

- Single validated `AnalyticsFilter` parsed server-side for web partials,
  REST endpoints and tool calls. Dashboard filter bar serializes to
  allowlisted URL query state; back/forward/reload preserve it; partials
  re-validate every value.
- External API enforces token-bound site/source plus the same filter model;
  analytics tokens gain no import/chat/model power (API-04).
- Assistant scope is a real boundary:
  `ChatBody → validate_scope/ValidatedScope → run_investigation →
  bounded tool arguments → evidence URLs`. New selectors (traffic, bot,
  category, provider, purpose, search, status_class, source) travel the
  whole chain; model arguments cannot omit/override/widen them — the trusted
  scope overwrites model values before execution, and unknown values fail
  closed. New tests: offline hostile-override (model attempts widening)
  and exact replay. Product tier/egress and exhausted allowance unchanged;
  no unrelated model-history or cost-display fixes.
- Evidence URLs carry the full selector set via the single trusted
  formatter; unknown tool names still yield no link.

## 5. Slices

### Slice A — contract, catalog, queries, services, scoped API, trusted tools (AUTHORIZED)

Files: `app/analytics/rules.py`, `app/analytics/classification.py` (new),
`app/analytics/contracts.py`, `app/analytics/queries.py`,
`app/analytics/service.py`, `app/db/database.py` (function registration),
`app/api/routes_analytics.py`, `app/api/schemas.py`,
`app/ai/tools/definitions.py`, `app/ai/service.py`,
`app/api/routes_chat.py`, `app/web/evidence.py`,
`config/bot_rules.yaml` (v3, 75 rules), `clients/logcarve_api_client.py`
(only if it wraps analytics params — check), `docs/external-api.md`
(endpoint rows), `THIRD_PARTY_NOTICES.md`, `CHANGELOG.md`.
Authored sources live in `assets/src`; served output rebuilds into
`app/web/static/` (Slice A needs no asset change; noted for Slice B).
Locale file is `config/locales/en.json` (Slice A adds no keys unless chat
errors need them).
Depends on: pinned LogWerk commit `d7ab01cae910fdd0c5165ee8378506c081c7124a`;
MIT text + copyright retained verbatim (see §6); source → destination →
new-work mapping recorded. Keep the five existing rule IDs.
Acceptance: ANA-01, ANA-03, ANA-04, ANA-05, API-01, API-03, API-04, API-05,
AUTH-02, PRIV-03. Neutral role wording kept throughout.
Tests: unit (rules precedence incl. overlapping/malicious/mixed-case UAs,
contracts incl. contradictory combos, classifier SQL-vs-Python agreement),
integration (hand-counted overlap/empty/NULL-UA fixture, API endpoints +
invalid/unknown selectors, cross-site/source denial, chat-off/provider-
unreachable, hostile-override + exact replay, cross-consumer equality),
benchmark recording (100k classification timing, no SLO assert).
Gates before commit: focused tests, full locked unit+integration, Ruff,
lock check (`uv lock --check`, no new dependency expected).

### Slice B — dashboard: charts, tables, bot drilldown, explorer (NOT AUTHORIZED YET)

Files: `app/web/routes.py`, `app/web/templates/pages/*.html`,
`app/web/templates/partials/*`, authored `assets/src/{css,js}/` rebuilt to
`app/web/static/`, `config/locales/en.json`.
Content: requests/errors/bytes timelines, status breakdown, traffic/bot
shares, paths by hits/errors/bytes, referrers, resource kinds, browser/OS
(claimed), weekday/hour heatmap, pseudonymized clients, named-bot drilldown
(requests/shares/status/bytes/paths/404s/robots/sitemap, allowlisted sort,
paging), sanitized request explorer (time/method/path/status/bytes/
minimized referrer/UA/pseudonym/classification, newest/oldest, bounded
search). Every selection changes every panel; empty states and
`available: false` timing notices visible; chart + accessible data table
throughout; filter changes reset offsets; safe URL state across
navigation/paging/reload.
Acceptance: ANA-02, UI-01, UI-02, UI-03, UI-04, UI-05.
Tests: integration (filter propagation, URL state) + repeatable Playwright
(keyboard, narrow/desktop, both themes, populated/empty, back/forward,
local assets only, real Chart datasets, paging/sorting), console/network
clean.

### Slice C — synthetic demo data, compatibility, measured scale (AUTHORIZED 2026-11-01, DELIVERED FOR INDEPENDENT RUNTIME VERIFICATION)

Decision (concrete, review-accepted): preserve the original T8 fixture
untouched; add one additive synthetic fixture with hand counts exercising
the new panels and traffic/bot controls; accept only explicitly approved
synthetic fingerprints; preserve existing auth/spend/allowance/import
history; refuse foreign stores. Test the candidate on a unique isolated
project/port before any reversible local demo update; published snapshot
and original live demo stay unchanged until a tested candidate exists.
Docker/browser execution stays with the independent local runner; no
retry or weakening of controls from the coding session.
Acceptance: ING-04, DB-01, OPS-02, OPS-03, QA-01.

Status 2026-11-01 closeout: Slice C was delivered on
`feature/traffic-analytics` as the combined 120-row dataset
(30 T8 rows 26–28 Oct untouched + 90 rich rows 29–31 Oct under unchanged
`example-combined`), pinned expectations in
`tests/fixtures/expected/demo_slice_c.json`, two-fixture probe/seeder,
tracked isolated candidate procedure
(`scripts/demo/verify_candidate.sh`, project `logcarve-demo-candidate`,
loopback 8091), combined-window demo URL (26 Oct–01 Nov), and the accepted
B legacy-test update (`status=404` preserved across navigation; behavior
unchanged). STOP for independent runtime verification (candidate Docker
run, offline smoke, protected Playwright incl. the updated B case, and
the typical whole-page 100k benchmark, and the persistent-demo update at
clean source `e81d2d0`. No claim beyond the evidence in
`docs/verification.md`.

Non-goals (recorded, not silently promoted): gzip/custom formats, rotation,
GeoIP, raw-IP views, session reconstruction, live ingestion, MCP server,
webhooks, model-history/cost-display fixes, paid replay/allowance reset.

## 6. Provenance and licensing

- LogCarve itself is **Apache-2.0** (accepted 2026-10-29, see `LICENSE`).
  Upstream LogWerk rules retain MIT.
- Upstream: LogWerk, MIT, pinned commit
  `d7ab01cae910fdd0c5165ee8378506c081c7124a`, source file `parser.js`
  (`botRules`, 75 named entries), behavior reference `README`/`app.js`.
  The upstream LICENSE notice is authoritative even where the README
  names differ: retain the MIT text and copyright verbatim, do not invent
  copyright. Per the supplied reference file the notice reads
  `Copyright (c) 2026 Batios`.
- Before any adaptation: pin commit, retain MIT text + copyright in
  `THIRD_PARTY_NOTICES.md`, record source/destination/new-work mapping
  (75 patterns → `ua_contains`/`ua_regex` + provider/purpose claims +
  category remap + precedence order + CLI/headless/scanner→automation
  remap are new work), update the stale "no LogWerk material imported"
  statements in notices/config headers. Functional inspiration only, no
  wholesale copy, no workflow-instruction reads, public reference source
  only, legitimate UA/provider names are traffic data (not attribution),
  never sample logs.
- Project licensing itself stays an owner decision only where still open
  (GOV-02); Apache-2.0 for LogCarve is decided.

## 7. Review gates

1. Scope, gap verdicts, accepted ANA-04/ANA-05 + new API-05/UI-05, and the
   full-75 rule-catalog approach.
2. Provenance recording location and the Slice A file list.
3. Demo/rollback decision (§Slice C) and runner-gated browser/scale checks.

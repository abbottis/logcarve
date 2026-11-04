# Hackathon contributions and provenance

The supplied spec identifies the prior LogWerk project and requires transparent separation of reused work from LogCarve contributions created from 2026-10-26 onward. This file records source provenance and development contributions; it does not certify event eligibility.

| Date | Contribution | Origin | Status/evidence |
| --- | --- | --- | --- |
| 2026-10-28 | Directory scaffold, project instructions, four project skills and derived planning/configuration docs | New LogCarve preparation from supplied v0.4 spec and official Muse docs | Local files; no application behavior claimed |
| 2026-10-28 | `docs/technical-spec.md` | Owner-supplied German specification v0.4 | Unmodified snapshot; checksum in `spec-provenance.md` |
| 2026-10-31 | External client `findings` route correction and verification | New original LogCarve change implemented with AI assistance at the owner's request; no LogWerk import | Existing real-HTTP tests pass; full suite 137 passed in clean and conflicting environments; see `verification.md` |
| 2026-11-01 | Bot rule catalog v3: 70 LogWerk `botRules` patterns/names/provider-purpose labels adapted (pinned commit `d7ab01c`, MIT retained verbatim in `THIRD_PARTY_NOTICES.md`), 5 pre-existing LogCarve rule IDs kept, 2 original rules added (UptimeRobot monitoring, generic suspected-automation fallback); category/ordering/matcher remaps are new LogCarve work | Mixed adaptation with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data | `config/bot_rules.yaml` v3 (77 entries); see Slice A evidence in `verification.md` |
| 2026-11-01 | Analytics completion slices A/B/C on `feature/traffic-analytics` (clean `e81d2d0`): traffic classification, scoped API and trusted assistant filters; rich dashboard panels with traffic/bot controls, sortable bot drilldowns and sanitized request explorer; combined 120-row synthetic demo dataset with probe/seeder and isolated candidate procedure | New LogCarve work implemented with AI assistance at the owner's request plus independent AI-assisted planning, review and testing; no LogWerk application code | Independently verified per `verification.md`: 428 unit/integration, 22 E2E, 53/53 API probe, 8/0 candidate Compose, 24/0 offline smoke, 32-case browser matrix |
| 2026-11-01 | Acceptance-readiness corrections at `bb272a9` on `feature/acceptance-polish-2026-11-01`: display-timezone catalogue (A), three offline AI evidence/cost/citation corrections (B), source-change quality on every tool plus decoded scope validation (C); this documentation closeout | New LogCarve work implemented with AI assistance at the owner's request plus independent verification; no LogWerk application code | Independently verified per `verification.md`: 480 unit/integration, 24 E2E, 121-check offline probe, 599-zone catalogue, 8/0 candidate Compose, 24/0 offline smoke, 32-case browser matrix; Muse implementation with separate AI-assisted planning, review and testing — no exclusive authorship claim |
| 2026-11-01 | Owner-UX Stage B on `feature/owner-ux-review-2026-11-01`: 8-column sortable Requests overview with per-row details, original conflicting-bot-identity candidate (`sec-conflicting-bot-identity` v1, explicit 9-token set, security ruleset v2, bot catalog 77 unchanged), largest-responses retarget, plus the five Stage A coordinator fixes | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk import, no application code copied | `config/security_rules.yaml` v2, `app/analytics/conflict.py`, shared query/service/API/dashboard path; 529 unit/integration pass per `verification.md`; E2E/browser + Docker proofs pending coordinator |
| 2026-11-01 | Owner-UX closeout (docs-only): independent verification of the Stage A+B slice at public HEAD `f0182fb` (app anchor `ffaf737`, image from `a087c3e`); live 8080 updated with the exact tested image | New LogCarve verification/closeout work implemented with AI assistance at the owner's request; no LogWerk import | Independently verified per `verification.md`: 536 unit/integration, 29 E2E, 78+53 API, 121 offline mock, 8/0 candidate + 24/0 offline Compose, 36+8+12 browser checks on candidate and live demo; owner acceptance pending |
| 2026-11-01 | LogWerk-parity T1b storage foundation on `feature/logwerk-parity-2026-11-01` (uncommitted): nullable enrichment metadata with explicit policy tags, AES-256-GCM original-IP store, bounded keyset reprocess, immutable source/site binding, atomic migrations, exact timeout accounting, fail-closed retention | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; `cryptography` 50.0.2 dependency recorded in `THIRD_PARTY_NOTICES.md` | 61 focused T1b tests plus full 661 unit/integration green in clean and conflicting environments per `verification.md`; independent review pending |
| 2026-11-01 | LogWerk-parity T2a shared analytics C/D plus T1b preflight closeout and the seven-review-finding correction (exact global p95 ranking, shared timing alignment, AI candidate/comparison scoping, bounded distributions, exact referrer tuples/relation, alias-extends-primary CLI, exact-path selector) on `feature/logwerk-parity-2026-11-01` | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | Focused T2a tests plus full unit/integration green in clean and conflicting environments per `verification.md`; independent reinspection pending before T2b |
| 2026-11-01 | LogWerk-parity T3a API/export completion on `feature/logwerk-parity-2026-11-01`: ten versioned API routes plus Bearer/session full-result CSV+JSON export (single owned read snapshot, bounded chunks, 250000 cap/413, Unicode-aware formula protection, reproducibility metadata on both transports, display-timezone/sort recording), int64-exact comparison metrics, fractional window/journey precision; assistant/tool/stdlib-client expansion explicitly deferred to T3b | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | 27 focused T3 API/export tests + 7 formula-classifier unit tests per `verification.md`; full 777 unit/integration green in clean and conflicting environments; independent reinspection pending; T3b/tools/full UI/follow/GeoIP not claimed |
| 2026-11-01 | LogWerk-parity pre-T4a export-client strictness follow-up on `feature/logwerk-parity-2026-11-01` (prior HEAD `7c0aee2` preserved): strict bounded JSON `export/1` envelope validation (mandatory metadata/schema_version/row_count, object rows, strict grammar), strict CSV validation (unique header, exact width, pre-reader oversize via bounded `readline()` records, strict quoting), http(s)-only redirect validation with userinfo/port/downgrade refusal, owned-COMMIT-failure `store_unavailable` instead of silent success, external CLI historical 3-document default plus validated baseline/selector flags, honest `export/1` test fixtures | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | 84 focused strictness tests plus full 927 unit/integration green in clean and conflicting environments per `verification.md` (2 live-loopback tests skipped in sandbox, root reruns post-freeze); independent review pending before T4a |
| 2026-11-02 | LogWerk-parity T4a private-IP web slice on `feature/logwerk-parity-2026-11-01`: session-gated original-IP Requests display bound by internal row id under the same read snapshot (full default only when unset; corrupt preferences fail closed to pseudonym-only), server-side suffix masking with validated hidden octet/hextet counts (scoped/mapped IPv6 handled, no plaintext fallback), CSRF/session POST settings persistence without key edit/display, POST-only exact-IP search translating transient input to the safe HMAC pseudonym (legacy spelling identity kept, never echoed in URL/history/errors), shared enrichment filters (path_exact, host/HTTP/MIME/cache/TLS, timing/upstream availability, finite ranges) in web params/canonical/nav/htmx/paging, safe http/https referrer links, full-result download controls with an every-mode pseudonym-export note, truthful pseudonym-sort labeling, compare_digest-safe CSRF, BFCache/pageshow refresh with historyCacheSize 0 and no-store preserved | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | 14 unit + 30 integration T4a tests plus updated replay contract per `verification.md`; full 971 unit/integration green; Playwright slice recorded BLOCKED in the implementer shell sandbox (environmental, pre-existing E2E errors identically) for coordinator execution; reports/saved views/comparison/refresh/Help audit explicitly deferred to T4b/T4c; independent review pending |
| 2026-11-02 | LogWerk-parity T4a corrections on `feature/logwerk-parity-2026-11-01` (prior HEAD `b1d17b4` preserved): shared exact `client` HMAC-equality selector through AnalyticsFilter/parameterized WHERE/service/API/export/tool/ValidatedScope/ChatBody/evidence/canonical/nav (exact-IP POST sets `client`, preserves text search and sort, resets offset; adversarial UA/path HMAC embeddings no longer match); every Ask selector (incl. exact client, native false/0) wired through authored+served Ask JS and data attributes; real 16KiB streaming body bound with duplicate/malformed rejection and 400/413 before buffering (auth first, no multipart); banner maps internal unavailable codes to fixed English guidance; upstream timing renders independently of request timing; settings/IP-search redirects rebuilt from validated allowlisted state | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | 23 focused correction tests plus 2 contract updates per `verification.md`; full 994 unit/integration green (2 skipped, pre-existing loopback-env); Playwright slice incl. new chat-POST capture test recorded BLOCKED in the implementer shell sandbox (environmental browser-launch denial, pre-existing tests error identically) for coordinator execution; independent review pending before T4b1 |
| 2026-11-02 | LogWerk-parity T4b1 report UI (performance/SEO/referrers) on `feature/logwerk-parity-2026-11-01` (prior HEAD `6d92231` preserved): reviewed-T4a residuals closed first (IP-search form action carries the allowlisted explorer sort while shared nav stays sort-free; journeys/journey_entries bounded evidence fits 1600 chars via compact model-facing limitation notes with full service/API payloads unchanged and the 1600/65KB bounds intact), then real navigable /performance (latency percentiles, slow-endpoint rankings, cache ratio+304 note, measured-MIME-vs-inferred, HTTP/TLS/host), /seo (bot 3xx/4xx/5xx per path+bot with exact drilldowns, scoped AI-only observed paths with universe caveat) and /referrers (sanitized full paths, internal/external SQL narrowing, broken-inbound 404s) pages sharing the filter engine, server paging/sorts, local Chart.js plots with table alternatives, honest coverage/limits and central English keys | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies | 12 focused web integration tests plus 2 protected Playwright tests per `verification.md`; full 1005 unit/integration green (2 skipped, pre-existing loopback-env); Playwright execution recorded BLOCKED in the implementer shell sandbox (environmental browser-launch denial, pre-existing tests error identically) for coordinator execution; journeys/security-rate UI (T4b2), saved views/comparison/refresh/Help (T4c), follow/GeoIP (T5) explicitly not claimed; independent review pending |
| 2026-11-02 | LogWerk-parity T5a offline GeoIP on `feature/logwerk-parity-2026-11-01` (prior HEAD `abdf69a` preserved, incl. inherited T4c refresh/XHR-association completion): genuine local MMDB country reader (DB-IP Country Lite only, `DBIP-Country-Lite` type gate, strict reserved/private/loopback/link-local/unspecified/documentation/multicast exclusion incl. IPv4-mapped, no-handle-leak unavailable, graceful unconfigured/required-fail-before-write), transient validated-IP derivation before discard/encryption, nullable `country_code`/`geo_source`/`geo_release`/`geo_status` migration 0007 with read-only-source reprocess enrichment and stable core IDs/HMAC/auth, shared `country`/`UNKNOWN` selector through every consumer (list/timeline/entry/security/comparison, API/export/AI tools/Ask/saved views/refresh/drilldown), exact breakdown + coverage + CC BY 4.0 credit link on country pages, XHR-keyed refresh applied-state with reversal/error coverage | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; `maxminddb` 3.2.0 pinned unconditionally (`Requires-Python: >=3.10`, runtime tested 3.12.16 only) and recorded in `THIRD_PARTY_NOTICES.md`; genuine MMDB file stays outside Git and Contributor context | 44 unit + 10 integration T5a tests plus 1 new T4c inflight reversal/error browser test per `verification.md`; full 1115 unit/integration green in clean and conflicting environments; Playwright execution recorded BLOCKED in the implementer shell sandbox (environmental browser-launch denial) for coordinator execution with the coordinator-mounted genuine DB; follow/rotation (T5b), release and owner acceptance explicitly not claimed; independent review pending |
| 2026-11-02 | LogWerk-parity T5a independent-review corrections on `feature/logwerk-parity-2026-11-01` (prior HEAD `31af5eb` preserved): stale automatic-response cancel before OOB/history swaps with own-XHR dispatch sequencing (newer explicit Apply wins, POST/401 drafts preserved, save target moves on accepted swaps only, country joins OOB controls), shared DB-IP credit partial on every country-filtered page with travelling export/CLI provenance, honest Unknown/unavailable/legacy copy with client-address estimate rename, exact-anchor asset guard with Node regression tests, typed `get_report` countries with scope override plus CLI `countries`/`--country` and local country chart | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data; no new dependencies; genuine MMDB file stays outside Git and Contributor context | 7 new integration + 4 new client strictness T5a tests plus updated reversal/draft-only/country browser tests per `verification.md`; full 1126 unit/integration green in clean and conflicting environments; Playwright execution recorded BLOCKED in the implementer shell sandbox (environmental browser-launch denial, no retry) for coordinator execution with the coordinator-mounted genuine DB; T5b, release, manual acceptance and independent review explicitly not claimed |
| 2026-11-02 | LogWerk-parity T5b1 corrections + T5b1c replay guard on `feature/logwerk-parity-2026-11-01` (prior HEAD `985d363` preserved; three inherited dirty files + two inherited test files continued, commits `a335f66` + `886ddbf`): carry-aware exact grouped-byte ordering, strict ISO/Combined offset validation with safe UTC bounds, rejecting explicit empty custom size/bytes while absent stays None-mapped; batch replay verifies the stored core/HMAC before attaching an encrypted original, refusing source-mutated associations with safe counts | New original LogCarve work implemented solely by Muse Spark 1.3 Contributor (medium, Contributor ON), no subagents; no LogWerk application code, session/person inference or sample data; no new dependencies; no real logs, keys, provider calls or push/main | 2 new replay-guard integration tests (defect reproduction + valid control) plus 28 inherited focused correction tests green; full suites NOT repeated per consolidated-pass authorization; independent review pending |
| 2026-11-02 | LogWerk-parity T5b2 follow/rotation + T5b3 helpers/readiness/docs closeout on `feature/logwerk-parity-2026-11-01` (commit `a6976df`): bounded opt-in CLI `follow` with durable checkpoints, honestly labeled generation identity, atomic batch+checkpoint commits, append/restart/rename-drain/copytruncate/replacement/rotation handling, once-per-restart prefix validation with taint refusal, batch-prefix adoption or explicit refusal, plain/gzip rotated-archive replay with prefix validation; coverage import history bounded with explicit truncation and exact SQL-SUM aggregates; `/readyz` supported-schema gate (MAX 8 + structural checks); coordinator-executed `scripts/upgrade_demo.py` (protected backup, hash proofs, image-only rollback) and `scripts/benchmark_synthetic.py` (deterministic 100k/1M harness); Ask Save/Refresh capability flags; corrected country wording, Lucide 20-icon notice, secret-scan finding record with verified commit SHA | New original LogCarve work implemented solely by Muse Spark 1.3 Contributor (medium, Contributor ON), no subagents; no LogWerk application code, session/person inference or sample data; no new dependencies; genuine MMDB file stays outside Git and Contributor context; no live watcher/service, no shipped translations, no browser file import UI | 10 unit + 15 integration follow tests, 4 readiness + 5 helper + 2 UI integration tests green (focused); full suites, protected browser E2E, secret history scan and independent security/release review NOT RUN (coordinator-owned after freeze); native x86-64 NOT RUN; owner acceptance pending |
| 2026-11-02 | LogWerk-parity documentation-only final receipts on `feature/logwerk-parity-2026-11-01` (clean code anchor `84f440f`; canonical equivalent `d62cb5a` on `local/logwerk-parity-2026-11-02`; 33 local commits reconciled, tracked trees IDENTICAL and clean): no application/test/script/asset/config/lockfile/schema change; coordinator-observed consolidated suite 1263 PASS at `7f0c20d`, 48 affected-file rerun at `84f440f`, protected browser 47+1-corrected plus 24 actual-image checks (both themes, IP-mode transitions, 599 zones, zero console/network/overflow errors), Ruff/format/lock/asset guards, redacted Gitleaks (two known false positives only, zero incremental findings, no authoring-tool hits), fresh ARM64 candidate 9/0, FINAL native ARM64 offline internal-network smoke 24/0 on image `8fcda...b22abd`, genuine offline DB-IP Country Lite November 2026 MMDB pipeline PASS, 1M benchmark observed timings incl. real-route 413 proof, ACTUAL local activation of 8080 at schema 8 (upgrade 4 → 8, 120 rows preserved, protected backup + image-only rollback) | Status/docs record only, implemented solely by Muse Spark 1.3 Contributor (medium, protections ON), no agents; no LogWerk application code, session/person inference or sample data; actual MMDB/key material stays outside Git/image/Contributor; Muse implementation with separate coordinator verification — no exclusive authorship claim | See `verification.md` final receipts: PAR-08/PAR-09 implemented, tested and activated; live 8080 healthy; product AI OFF; historical real AI-02 INCOMPLETE 2 of 3; native Linux x86-64 NOT RUN; owner manual acceptance + video rehearsal OPEN; no push/merge/exposure/deployment |
| 2026-11-02 | Authorized AI-provider settings extension on `feature/logwerk-parity-ready-2026-11-02` (ADR 0004, owner-accepted): genuine native server-side adapters for Meta (preserved), OpenAI Responses (`gpt-6-luna`), Gemini generateContent (`gemini-3.5-flash-lite`, ordered thoughtSignature replay) and Claude Messages (`claude-haiku-5-5`, verified against the official Anthropic SDK `ModelParam` via Context7) with model-specific verified pricing and exact trusted native endpoints; DB-backed backend AI Settings (enable/provider/model, per-provider AES-GCM keys under dedicated `AI_SETTINGS_KEY`, per-provider policies, Anthropic workspace ID) with blank-keep/remove/env-managed semantics; per-investigation binding pins with mid-run fail-closed; separate explicit bounded runtime usage grant (initially none) alongside the preserved T8 smoke ledger; migration 0009 plus `ai-allowance-grant` CLI | New original LogCarve work implemented solely by Muse Spark 1.3 Contributor (medium, Contributor ON), no subagents; no LogWerk application code, session/person inference or sample data; no new dependencies; no real logs, keys, provider calls, push/main or production deployment | Focused unit/integration suites for all four providers, settings store, gate, registry, allowance and web settings; consolidated full unit/integration run per `verification.md`; protected browser E2E authored for coordinator execution (shell sandbox blocks Chromium); independent security/tool review pending before activation |
| 2026-11-03 | First-Linux-CI portability correction on `feature/evidence-revalidation-2026-11-03` (prior HEAD `2ce8787` preserved): CI asset build moved before tests so ignored/regenerated static JS exists for integration tests; explicit `localtime`/`posixrules`/`posix/*`/`right/*` filter in the display-timezone catalogue (pinned Python 3.12 still reports `localtime`); timezone tests assert the installed-database contract plus a hermetic controlled-catalogue regression | New original LogCarve correction implemented with AI assistance at the owner's request; no LogWerk application code, no new dependencies | Focused 19 timezone integration tests PASS plus Ruff/format/diff checks per `verification.md`; full corrected CI runs on GitHub after push (coordinator-owned) |

No LogWerk application code, assets, session/person inference or sample data have been imported. The 70 adapted rule-catalog patterns are recorded above and in `THIRD_PARTY_NOTICES.md` with the retained MIT notice. The application otherwise uses third-party dependencies and browser assets listed in `THIRD_PARTY_NOTICES.md`; their licenses and notices remain applicable. Before each import, record source URL, commit/version, destination, license/notices, what predates the event and what changes are new. Keep the public demo/submission wording consistent with this record.

Before submission: independently review the current Official Rules, verify eligibility/prior-work requirements and prepare the actual demonstration. Original LogCarve code and documentation are licensed Apache-2.0; third-party components retain their own licenses. Credit terms and an API balance do not establish submission eligibility or account access. Publishing a repository or submitting material has not been authorized by this scaffold task.

## Analytics closeout, 1 November 2026

The backend, deterministic analytics, authentication/API, bounded assistant,
browser dashboard and local demo were developed under owner direction:
Muse implementation with separate AI-assisted planning, review and testing.

- Original implementation: parser, SQLite import/replay/backup/retention,
  shared analytics, scoped API, bounded model tools, local browser UI,
  and the traffic-analytics slices (classification, dashboard panels,
  bot drilldowns, request explorer, 120-row synthetic demo).
- Third-party code/assets: the pinned packages and retained notices in
  `THIRD_PARTY_NOTICES.md`; no LogWerk application-code imports (the
  70-pattern rule adaptation of 2026-11-01 is recorded separately above
  with the pinned commit and retained MIT notice).
- Actual verification at clean `e81d2d0`: 428 unit/integration tests, 22
  browser E2E tests, a 53/53 synthetic API probe, 8/0 candidate Compose
  run, 24/0 offline smoke and a 32-case browser matrix passed per the
  independent runner. See `verification.md` for environments and
  historical results.
- Authorized real model test: two investigations completed with evidence;
  the third stopped at its context bound. AI-02 remains incomplete and
  native Linux x86-64 installation remains unverified.
- Publication: a consolidated checkpoint branch preserves the existing
  remote main as its parent. Detailed development branches remain local;
  the publication commit is not a claim that all work occurred in one step.

## Parity T4b2 journeys/entry-paths/security report UI, 2 November 2026

Owner-authorized LogWerk parity T4b2 (no new approval loop),
implemented solely by Muse Spark 1.3 Contributor (medium,
Contributor ON) with sandbox + approval ON: navigable Journeys
page over the shared journey service (ranked list, entry-path
aggregation, opaque timeline detail; no visitor/session/people
labels), expanded Security page (rates, UTC-minute peaks,
sequences, 401/403 candidates; 401 as challenge, never failed
login; heuristic candidates, never confirmed attacks), tool
evidence mapped to the pages that reproduce each read, and the
host-only referrer URL-group model clarification (paths withheld,
no egress widening, no provider call). Original LogCarve code
remains Apache-2.0; no LogWerk application code was imported
(70-pattern MIT rule adaptation of 2026-11-01 unchanged).
Synthetic fixtures only; no real logs, keys, provider calls,
push/main/deploy or release/acceptance claims. Independent review
stays required before T4c.

## Parity T4b1 review corrections, 2 November 2026

Owner-authorized LogWerk parity corrections before T4b2 (no new
approval loop), implemented solely by Muse Spark 1.3 Contributor
(medium, Contributor ON) with sandbox + approval ON: page-local
report state preserved across Apply/canonical/history/paging (native
GET + htmx, no cross-page sort leaks); approved full sanitized
referrer-URL overview added alongside the retained 404-target view
(LogWerk `renderRefererUrls`, no copied metric engine, no new
storage/dependencies); referrer supporting-data links honestly
labelled as related scope (no exact-row pretense, no invented URLs);
internal tool hrefs map to the implemented Performance/SEO/Referrers
pages with page-local view/sort/relation; slow-endpoint copy reads
measured requests with backend ranking/keys/API unchanged. Original
LogCarve code remains Apache-2.0; no LogWerk application code was
imported (70-pattern MIT rule adaptation of 2026-11-01 unchanged).
Synthetic fixtures only; no real logs, keys, provider calls,
push/main/deploy or release/acceptance claims. Independent review
stays required before T4b2.

## Parity T4c saved views/comparison/refresh/Help, 2 November 2026

Owner-authorized LogWerk parity closeout of T4 UI after reviewed
T4b2 (no new approval loop), implemented solely by Muse Spark 1.3
Contributor (medium, Contributor ON) with sandbox + approval ON:
frozen T4b2 display defects corrected first (literal-newline E2E
fixture fixed with accepted/rejected asserts, journey filter-state
serialization, display-timezone instants with DST-correct offsets,
microsecond duration labels, central security labels); session-owned
saved filter views with CSRF/per-user ownership/allowlisted
paths/validated filters and bounds; explicit current-vs-baseline
comparison page and evidence replay to the actual executed halves;
opt-in OFF-default read-only refresh; comprehensive Help; central-
English locale readiness with no shipped translations. No file
import UI, no locale selector, no template/JS metric
reimplementation. Original LogCarve code remains Apache-2.0; no
LogWerk application code was imported (70-pattern MIT rule
adaptation of 2026-11-01 unchanged). Synthetic fixtures only; no
real logs, keys, provider calls, push/main/deploy or
release/acceptance claims. Independent review stays required;
E2E recorded BLOCKED in this shell sandbox for coordinator
execution, follow/real-GeoIP not claimed.

## Parity T4c independent-review corrections, 2 November 2026

Owner-authorized bounded corrections of the six confirmed T4c
independent-review findings (no T5a), implemented solely by Muse
Spark 1.3 Contributor (medium, Contributor ON) with sandbox +
approval ON: save-current replay of the displayed canonical state
after successful htmx Apply (failure retains last state, no raw
IP/CSRF in URLs); comparison previous/custom baselines surviving
filter-bar Apply/push/refresh with no silent default; shared UTC
datetime-local formatter keeping minute-only form where exact and
seconds/microseconds otherwise (global Apply no longer floors
fractional evidence windows); immediate central refresh ON/OFF state
with dirty/hidden/modal/focus pause and no hardcoded English;
owner-only saved-view update UI control; positive signed-64-bit
saved-view id bounds before DB binding with fixed missing-view
answers. Original LogCarve code remains Apache-2.0; no LogWerk
application code was imported (70-pattern MIT rule adaptation of
2026-11-01 unchanged). Synthetic fixtures only; no real logs, keys,
provider calls, push/main/deploy or release/acceptance claims.
Independent review stays required; protected E2E recorded BLOCKED in
this shell sandbox for coordinator execution.

## Parity T5b1 timestamp compatibility + numeric domain, 2 November 2026

Owner-authorized first T5b slice (follow/rotation and
activation/benchmark helpers explicitly deferred), implemented
solely by Muse Spark 1.3 Contributor (medium, Contributor ON)
with sandbox + approval ON. Declared custom timestamp modes
(`combined` default, `Z`/offset-required ISO-8601, epoch seconds /
milliseconds with explicit unit; UTC normalization at documented
microsecond precision; fixed rejections), int64 response-size
domain enforced before conversion (`invalid_bytes`, no
conversion-limit crash, no unbindable value), exact split-half
byte sums end to end (no float, no database overflow), fractional
journey/window compatibility to the microsecond, plus the two
frozen-review browser-harness corrections (single phase-aware
route handler; stored-Unknown vs unavailable expectation). New
unit (53) and integration (7) tests; full suites green in default
and AI-enabled configurations; Ruff/format/lock clean. Original
LogCarve code remains Apache-2.0; no LogWerk application code was
imported. Synthetic fixtures only; no real logs, keys, provider
calls, push/main/deploy, follow activation or release/acceptance
claims. Independent review stays required; protected E2E recorded
BLOCKED in this shell sandbox for coordinator execution.

## Alternate model upgrade, 2 November 2026

Owner-requested alternate model upgrade (OpenAI cache-write
accounting/reservation, Sonnet `between_tools` low with signed
exact-content replay, Gemini `LOW` with pricing validity),
implemented solely by Muse Spark 1.3 Contributor (medium,
Contributor ON) with safeguards ON and no subagents; synthetic
fixtures only; no new dependencies or third-party code. Gemini and
Sonnet owner-authorized synthetic tool-to-evidence runs PASS on
2026-11-02; the OpenAI account quota block (429
`credit_balance_exhausted`) was the INITIAL historical result, not
validated successful at that time — see the
dated operational closeout in `verification.md`. A later owner-funded
synthetic retest on 2026-11-02 also PASS. Implementation provenance
remains Muse only. Original LogCarve
code remains Apache-2.0.

## Evidence provenance and revalidation, 3 November 2026

Owner-authorized small slice (Muse Spark 1.3 Contributor, medium,
Contributor ON, sole writer, no subagents; public source and synthetic
fixtures only; safeguards ON). Local evidence/findings now carry compact
source/generation provenance and a result digest through the shared
analytics/tool layer; a stateless signed receipt replays the exact
original scope through the same deterministic read with a fresh
observation time and reports current / changed / unavailable /
unverified. Local admin session + CSRF; zero model calls; no migration,
no new dependencies, no provider-wire change. Original LogCarve code
remains Apache-2.0.

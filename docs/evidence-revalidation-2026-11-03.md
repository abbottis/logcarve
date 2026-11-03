# Evidence provenance and revalidation (2026-11-03)

Owner-authorized SMALL slice: carry source/generation, exact time window and
filters with findings; re-check old investigations after rotation or
retention; distinguish evidence that still resolves. Existing scope approval
is sufficient; no migration, no new dependency, no architecture expansion.

## Acceptance mapping

- ANA-01: recheck reuses the SAME deterministic tool/query execution and the
  exact original scope (site, source, window, matchers, paging, bucket).
  Equal scope plus unchanged store yields an equal digest.
- ANA-03: provenance (rule/version, window, filters, observation time,
  coverage) already travels with findings; this slice adds compact
  source/generation heads and a result digest. Claims stay investigation
  candidates; nothing here asserts verified bot identity, compromise,
  anonymous IPs or raw snapshots.
- AI-02/AI-03: evidence envelopes keep tool_call_id/tool/filters/
  observation_time/coverage; provider projection is UNCHANGED (no new
  provider metadata, egress allowlist untouched). Provenance and receipts
  are local-only, returned to the browser.
- AI-04: recheck performs ZERO model calls and ZERO usage reservations and
  works with AI disabled, no provider key and no network.
- AUTH-01/AUTH-02: recheck requires the existing local admin session plus
  per-session CSRF (POST). Existing analytics Bearer tokens grant no chat
  or recheck power and are rejected. No persistent chat/history tables,
  no migration (root stays schema 9).
- PRIV-01/PRIV-03: receipts sign only bounded safe replay metadata and
  digests, never raw results. No raw paths, raw lines, original IPs,
  credentials or raw fingerprint internals travel to providers (provenance
  never enters the provider wire) and receipts never leave the server
  except as opaque strings to the authenticated browser.
- DB-02: retention semantics unchanged; recheck only READS. A scope whose
  selected events were removed by retention reports `changed` (partial) or
  `unavailable` (none left), never a clean `current`.
- PAR-08: follow/rotation generations are the reason rechecks can move:
  generation heads are reported so "same result, newer generation" stays
  distinguishable from "same result, same generation".
- UI-01/UI-02: one small affordance ("Recheck evidence") beside existing
  links, central `en` locale keys, visible current/changed/unavailable/
  unverified states. Existing hrefs keep working but are labeled as
  reruns of current data, never immutable archives.
- UI-04: no inline scripts, no CDN, no new dependency; existing
  `assets/src/js` build conventions only.

## Concrete scope

1. `app/ai/tools/definitions.py`: every envelope gains `provenance`
   (per-source generation seq/id, import head id, scope unique events,
   observed min/max, imports-truncated flag) and `result_digest`
   (SHA-256 over canonical JSON of `result` minus the two volatile
   observation timestamps `generated_at`/`observation_time`, named in
   `app/ai/receipts.py`). Computed inside the ONE owned read snapshot.
   No fingerprint, path, IP or secret content.
2. New `app/ai/receipts.py`: canonical JSON, digest, provenance builder
   helper, stateless HMAC-SHA256 receipt sign/verify over
   `{v, tool, filters, result_digest, provenance, observation_time}`
   keyed by the server `session_secret`. Receipts are opaque to the
   browser and carry no raw results.
3. `app/api/routes_chat.py`: attach `receipt` per evidence item on
   `POST /api/v1/chat/ask`; add `POST /api/v1/chat/evidence/recheck`
   accepting `{receipt}` (exact receipt scope is the ONLY scope; client
   filters are never trusted) plus legacy `{tool, filters}` which
   returns `unverified` without a current claim. Re-executes the same
   `execute_tool` path with a fresh observation time.
4. Status semantics: `current` (digest equal, same generation),
   `current` + `generation_changed: true` (digest equal, heads moved),
   `changed` (digest differs, selected events still resolve),
   `unavailable` (no selected events resolve), `unverified`
   (bad/missing receipt, legacy evidence). Signature errors fail closed
   (400, no execution). Unknown tools, foreign site/source and
   observation-time-only replays classify honestly.
5. `assets/src/js/ask.js` + `app/web/templates/pages/ask.html` +
   `config/locales/en.json`: Recheck button per evidence row, status
   text, scope/coverage line. Existing links remain, labeled as reruns.
6. Tests: `tests/integration/test_evidence_recheck.py` (synthetic only):
   unchanged replay, rotation/follow generation move, retention
   partial/full removal, same-count/different-evidence digest,
   tampered receipt, invalid tool/scope, foreign source, missing
   auth/CSRF, legacy evidence, Bearer-token rejection, AI-disabled run.
   One focused Playwright check for the new affordance.

## Non-goals

No schema migration, no chat-history persistence, no import/retention
policy edits, no provider wire changes, no budget changes, no live model
tests, no public deployment, no push/main modification.

## Independent-review corrections (2026-11-03, candidate d676b88)

Reviewer-reproduced defects, fixed in this same small change with
focused tests; no migration, no new dependency, no model calls, no
push/main modification.

1. Unicode/malformed signature robustness (`app/ai/receipts.py`
   `verify_receipt`): non-ASCII signatures (`'abc.é'`) raised
   `TypeError` from `hmac.compare_digest` instead of returning
   invalid. Every encode/compare/decode step is now guarded, plus
   strict shape checks (exact field set, non-empty tool, 64-hex
   digest, bounded length/payload ceilings). The endpoint still
   returns a safe 400 `invalid_receipt` and never executes a tool
   for such a receipt (HTTP path tested, with `request_id` parity).
2. False current on missing provenance (`build_provenance`): store
   read errors were swallowed into all-`None` heads, so a replay
   after `DROP TABLE follow_generations` returned HTTP 200
   `current` + `generation_changed` with null ids. The helper moved
   to shared analytics ownership (`app/analytics/provenance.py`,
   typed/parameterized bounded reads, `MAX_PROVENANCE_SOURCES = 64`
   with an explicit `complete` flag); failures now propagate through
   the safe `StoreUnavailable`/`ToolError` path instead of
   collapsing into null metadata. A capped listing (or any explicit
   incomplete provenance) returns `unverified`
   (`provenance_incomplete`), never `current`. A real known
   non-follow source (no row, store healthy) keeps `None` heads
   with `complete: true`.
3. Unsafe store handling (`POST /api/v1/chat/evidence/recheck`):
   `connect(..., read_only=True)` sat outside the `try` and any
   synthetic `connect` failure returned a bare 500 with no
   `X-Request-ID`. The whole replay now runs inside the existing
   `read_store` snapshot; handle-open, query-time and
   provenance-query failures yield structured 503
   `store_unavailable` with body/header `request_id` parity and no
   path/SQL/exception leakage (no file or directory creation). A
   plain `ValueError` unrelated to storage keeps its own 400.
4. `RecheckBody` hardening: `extra = "forbid"` (unknown fields fail
   closed 400 instead of silently changing behavior); legacy
   evidence returns `filters: None` (the untrusted client object is
   never echoed back as metadata); client `filters` riding
   alongside a receipt are ignored, never merged into the signed
   scope.
5. Tests: rotation coverage is now a genuine `run_follow`
   rotation/replay scenario (rename live file, follow the new
   generation from out-of-window records with `fresh_start=True`:
   `current` + `generation_changed`, original coverage intact) using
   `get_security_findings`, the existing report whose result is
   strictly window-scoped (summary/timeseries envelopes embed
   source-wide import stats that legitimately move with new import
   activity; metric definitions unchanged). Partial retention
   (`changed`) and full retention (`unavailable`) use
   `apply_retention`, with source-byte hashes proving
   retention/recheck never modify source bytes.
6. Browser: one real repeatable flow (fake provider injected into a
   synthetic local app) — real chat envelope + receipt, render the
   real button, click, assert `current`; synthetic retention wipe,
   click again, assert `unavailable`. Real local endpoint and CSRF,
   no provider network/billing. UI shows the recheck time, surviving
   coverage and original scope/source beside the state, with a live
   `role="status"` announcement; central `en` keys, textContent-only
   rendering, rerun-note kept.

## Final bounded correction (2026-11-03, clean `a812dc5`)

Reviewer-reproduced: the recheck handler treated a missing
`provenance.complete` marker as complete
(`old_provenance.get("complete", True)` /
`fresh_provenance.get("complete", True)`), so a genuine signed legacy
receipt with the marker removed returned HTTP 200 `current`. Unknown
completeness is never a positive claim: both old and fresh provenance
must now carry `complete` explicitly `True`, otherwise the replay
reports `unverified`/`provenance_incomplete` (missing, null,
wrong-type or false all withhold `current`). Earlier draft receipts
were never deployed, so no backward-compatible completeness
assumption is kept.

Copy (central `en`, `generation_changed` field preserved for
compatibility): `ask.recheck_current_new_generation` now reads "The
evidence still matches; source history has changed." The flag compares
import heads as well as follow generations, so a replay-only new
import attempt proves source/import-head provenance movement, not
necessarily new source events or a newer file generation.
`ask.recheck_unavailable` now reads "No selected log events are
available in the current data." Zero surviving selected events may
have been zero originally; emptiness alone never claims retention
removed anything. Status logic is unchanged: zero surviving selected
events stay `unavailable`.

Tests: new parametrized regression over signed receipts with
missing/null/string/numeric `complete` markers (all
`unverified`/`provenance_incomplete`); existing valid-`current`,
cap-`unverified` and storage-503 cases keep passing.

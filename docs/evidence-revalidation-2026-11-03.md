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

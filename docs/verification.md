# Verification record

## 2026-11-01 — Parity pre-T4a export-client strictness follow-up

Owner-authorized bounded follow-up BEFORE T4a on
`feature/logwerk-parity-2026-11-01` (prior HEAD `7c0aee2`
preserved, no amend), exact model `muse-spark-1.3-contributor` /
medium / Contributor ON; sandbox + approval ON, sole writer, no
subagents, no extra approval loop, no parent files/keys/private
history/real logs, no Docker/product/provider calls/push/main/
deployment. All application/test changes by the implementer.
Public/synthetic data only; the 120 fixtures, 77 bot rules,
HMAC/auth/usage and all previous commits preserved (no fixture,
rule or config changes). No browser import, no translations.
Independent review stays required before T4a.

Reproduced first on the frozen anchor `7c0aee2` (clean tree):
`_verify_export_file` ACCEPTED JSON with missing metadata,
missing rows, missing `metadata.row_count`, a trailing envelope
comma, a trailing rows comma and scalar row `42` (plus nested
duplicate keys and `NaN`, probed the same way); ACCEPTED CSV
header `path,status,bytes` with short row `/x,200`, header
`path,status` with long row `/x,200,extra`, and an unterminated
quoted final row; `_SafeRedirectHandler` forwarded synthetic
`Authorization` on `http://example.invalid:80/source` ->
`ftp://example.invalid:80/target` with no network used; an
injected COMMIT sqlite error rolled back yet `execute_tool`
still returned success; the CLI default (`--endpoint all`)
included `comparison` without baseline flags (live-loopback
`test_external_client_summary_crawlers_findings` failed HTTP 400
outside the sandbox). Normal owned snapshots, inside-halves
comparison, the 12-case ASGI export cleanup, 0600/exclusive
output ownership, partial cleanup and existing+symlink refusal
were retained (re-verified, not re-fixed).

Corrections (each re-probed before fixing, then covered by
controlled tests):

1. Strict JSON streaming validation
   (`clients/logcarve_api_client.py`): the exact `export/1`
   envelope is now mandatory — `metadata` object with
   `schema_version == "export/1"` and a non-bool integer
   `row_count` in `[0, 250000]` matching the header count,
   `rows` array of objects of matching length, `complete`
   exactly `true` — with strict grammar at every depth (no
   trailing commas, no duplicate keys, no `NaN`/`Infinity`,
   no unknown components, no trailing junk). Whitespace, key
   order, UTF-8, escaped quotes/newlines, chunk splits and
   large counts stay accepted; consumed input is dropped so
   the whole file is never held.
2. Strict CSV validation (`clients/logcarve_api_client.py`):
   valid nonempty unique header and exact header width on
   EVERY data row under `strict=True` quoting. A bounded
   `readline()`-only record iterator (never handle iteration,
   never unbounded `read()`) enforces the 1 MiB record bound
   BEFORE `csv.reader` can preallocate, while quoted
   multiline fields stay one record. Wide (3 MiB, many
   columns) and tall (quoted multiline past 1 MiB) hostile
   records fail after ~1 MiB + slice granularity, never the
   whole file. Documented limit: a same-count shortening
   inside one valid final cell is not cryptographically
   detectable; row drops, grammar breaks and network aborts
   (`IncompleteRead`/timeouts) are caught.
3. Redirects (`clients/logcarve_api_client.py`): only
   `http`/`https` targets, no credential-bearing userinfo, no
   malformed ports, same hostname (case-insensitive), same
   effective port except the canonical same-host `http`->`https`
   default-port (80->443) upgrade; every scheme change, host
   change, other port change and downgrade raises a safe
   error before forwarding. Proven for BOTH `fetch` and
   `download_export` (default opener carries the handler;
   synthetic Request/fake transports only, no real network).
4. Snapshot finalization (`app/ai/tools/definitions.py`): an
   owned COMMIT failure now rolls back and raises
   `ToolError(store_unavailable)` instead of returning
   success; caller-owned transactions stay untouched (even
   when COMMIT would fail). The trusted equal-halves
   comparison, evidence, ranking, 65 KiB wire and 1600-char
   bounds fixes are intact.
5. External CLI (`clients/logcarve_api_client.py`): the
   default again fetches only the three standalone documents
   (`summary`, `crawlers`, `findings`), preserving the
   historical success assertion. `comparison` is explicit
   opt-in with validated `--baseline-from`/`--baseline-to`
   (ISO, tz-aware, ordered, required together, comparison
   only); `--source`/`--limit`/`--offset` selectors are
   validated and forwarded to the endpoints that accept
   them. Fake-transport CLI/parser tests catch the old
   default-comparison failure without sockets.
6. Old client fixture bodies now carry the honest
   `export/1` schema (`schema_version` added in
   `test_t3b_corrections.py`, `test_assistant_stage_c.py`);
   no production check was weakened for a fixture.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/unit/test_client_strictness.py` | PASS | 84 passed: 10 malformed/redirect probes as regressions (missing components, trailing commas, scalar rows, nested dup keys, non-finite constants, bad metadata/markers, short/long/unclosed/dup-header CSV, ftp/userinfo/port/scheme matrix, COMMIT injection, CLI default/baseline/selector matrix); JSON empty/3000-row streamed with 7/13-byte chunks; CSV multiline/escapes/empty with 5-char readline slices; wide+tall oversized fail with bounded consumption proofs; safe-opener proof for fetch+download; caller-owned survival; real `ExportStream`->file CSV+JSON compat incl empty window, null timing, Unicode, verbatim hostile path, no original IPs |
| Full `tests/unit tests/integration` clean | PASS | 927 passed, 2 skipped (exit status read directly, no masking pipes) |
| Full suites conflicting env (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 927 passed, 2 skipped |
| Live-loopback `test_external_client.py` (2 tests) | SKIPPED here | Both skip in this sandbox (`loopback sockets are unavailable`); NOT executed, so no live-HTTP proof is inferred from the suite. Fake-transport CLI/parser regressions above executed and PASS. Root coordinator reruns the live-loopback test after the freeze |
| `ruff check` + `ruff format --check` | PASS | Both clean repo-wide (190 files formatted) |
| `uv lock --check --offline` | PASS | Resolved 42 packages, no manifest/lock delta (stdlib only) |
| 120 fixtures / HMAC / 77 rules / usage | PASS | Untouched: tree shows only 2 modified app/client files + 2 updated tests + 1 new test; no fixture/rule/config changes |
| Real AI / real acceptance / release | NOT RUN | No production transport, key, account or paid call; no native Linux/release claim; no full parity/T4 claim; stopping for independent review before T4a |

Correction: the prior T3b entry above labels its prior HEAD
`fbc1433`; the actual T3a application commit is `fbc1439`
(fixed below). The two live-loopback tests were SKIPPED by the
sandbox in every run on this page (recorded as skips, never as
executed proof).

## 2026-11-01 — Parity T3b assistant/client corrections (4 findings)

Owner-authorized bounded continuation on
`feature/logwerk-parity-2026-11-01` (prior HEAD `fbc1439`
preserved, no amend), exact model `muse-spark-1.3-contributor` /
medium / Contributor ON; sandbox + approval ON, sole writer, no
subagents, no extra approval loop, no parent files/keys/private
history/real logs, no Docker/product/provider calls/push/main/
deployment. All code/tests by the implementer. Public/synthetic
data only; the 120 fixtures, 77 bot rules, HMAC/auth/usage and
all previous commits preserved. No UI import, no translations.
Independent review stays required before T4a.

Reproduced first on the frozen tree (venv python, synthetic
stores only): owned `BEGIN` left `conn.in_transaction True` after
a successful `get_summary`; `get_report(report=comparison)` for
28Oct00Z–29Oct00Z returned `previous_window` 27Oct00Z–28Oct00Z
(outside the selected interval); `_verify_export_file` called
unbounded `handle.read()`; `open(dest, "wb")` overwrote existing
targets; the default `HTTPRedirectHandler` forwarded
`Authorization` cross-origin (coordinator Request-only probe).
No finding was already fixed.

Correction gates (each re-probed before fixing, then covered by
controlled tests):

1. Tool snapshot ownership (`app/ai/tools/definitions.py`): the
   envelope is now computed inside the `try`, the owned snapshot
   commits BEFORE `return` on success and rolls back on
   `ToolError`/store failures, while caller-owned transactions
   stay intact (no commit/rollback by the tool).
   `_execute_bounded_tool` still closes its handle before any
   provider await.
2. Trusted comparison (`app/analytics/service.py`,
   `app/ai/tools/definitions.py`, `app/ai/egress.py`): the model
   `comparison` report now compares equal halves INSIDE the
   selected window (`split_trusted_window_filter`: baseline first
   half, current second half; odd/sub-microsecond windows fail
   closed), with explicit `definition` + `parent_window` metadata.
   The explicit deterministic API/UI comparison
   (`baseline_from`/`baseline_to`) is unchanged. Model evidence
   carries both exact windows plus the definition; the bounded
   projection nests window pairs, hoists a uniform verdict, and
   omits only the derivable per-hour rate (full envelope and
   API/UI keep all seven metrics). Slow-endpoint evidence now
   carries the server `sort` (`avg_desc`) with an explicit
   rank label, so an average-ranked sample cannot read as a
   global p95 ranking. 1600-char/65 KiB bounds unchanged (no
   budget raised).
3. Client hardening (`clients/logcarve_api_client.py`, stdlib
   only): `_SafeRedirectHandler` keeps `Authorization` on
   same-origin/upgraded redirects and rejects cross-origin, port
   change and `https`→`http` downgrade with a safe error for
   BOTH `fetch` and `download_export` (fake-transport covered,
   no network/key). Downloads refuse pre-existing targets
   (including symlinks) before any request, create owned `0600`
   outputs via `O_EXCL`/`O_NOFOLLOW`, and remove ONLY the
   run-owned partial on every failure (`IncompleteRead`,
   timeouts included); messages never carry tokens or bodies.
   Verification streams from disk (no unbounded `read()`):
   CSV rows via the stdlib `csv` reader (quoted newlines and
   multibyte splits stay in-record), JSON incrementally with a
   bounded decoder buffer and per-row state (exact
   `metadata.row_count`/row count/`complete: true`,
   numeric/null/formula semantics preserved).
   `ExportStreamingResponse` ASGI `finally` cleanup, the
   12-case CSV/JSON matrix, 2.3/2.4 headers/first-body/row-body
   matrix (all closed), single-snapshot metadata/count/cap/rows
   and pre-header safe 503 are retained with no regressions to
   private-data, source/time/site scope, rule-version or schema
   safety.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/unit/test_t3b_corrections.py` | PASS | 24 passed: owned/caller-owned/error/ghost-writer snapshots; inside-split windows, outside-edge exclusion, hostile-time override, unsplittable fail-closed; bounded CSV/JSON verification (refusing wrappers, chunk splits, 8 bad bodies, numeric/null/formula); existing/symlink refusal, owned-0600 + midstream cleanup; redirect matrix + safe-opener fetch/download; ranking/windows evidence within 1600 chars |
| Updated `tests/integration/test_assistant_stage_c.py` | PASS | 28 passed: comparison asserts the inside split (baseline `[FROM, MID)`, current `[MID, TO)`, `parent_window`, definition) and hostile-time override inside the window; 09:30 rows kept as never-read outside edges |
| AI/egress/native-wire fake tests, outbound sockets denied | PASS | 206 passed, 2 skipped (loopback-only socket guard plugin in `/tmp`, not committed) |
| Full `tests/unit tests/integration` clean | PASS | 843 passed, 2 skipped |
| Full suites conflicting env (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 843 passed, 2 skipped |
| External client regressions | PASS (suites) / SKIPPED (live-loopback here) | Fake-transport and TestClient coverage executed in the full clean suite; the 2 `test_external_client.py` live-loopback tests SKIP in this sandbox (`loopback sockets are unavailable`) and were never executed proof here — see the pre-T4a follow-up entry above |
| `ruff check` + `ruff format --check` | PASS | Both clean repo-wide (189 files formatted) |
| `uv lock --check --offline` | PASS | Resolved 42 packages, no manifest/lock delta (stdlib only) |
| 120 fixtures / HMAC / 77 rules / usage | PASS | Untouched: tree shows only 4 modified app/client files + 1 updated test + 1 new test; no fixture/rule/config changes |
| Real AI / real acceptance / release | NOT RUN | No production transport, key, account or paid call; no native Linux/release claim; stopping for independent review before T4a |

## 2026-11-01 — Parity T3a API/export completion (PAR-07)

Owner-authorized bounded continuation of the uncommitted T3a
API/export slice on `feature/logwerk-parity-2026-11-01` (prior HEAD
`966c99b` preserved, no amend), exact model
`muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents, no extra approval loop, no
parent files/keys/private history/real logs, no Docker/product/
provider calls/push/main/deployment. All code/tests by the
implementer. Public/synthetic data only; the immutable 120-row
fixtures, 77 bot rules, core HMAC/auth/usage/consumed allowance and
all previous commits preserved. Assistant/tool/stdlib-client final
expansion stays a separately orchestrated T3b slice (not
implemented, not claimed); no approved API/export requirement
dropped.

Reproduced first on the frozen tree: the full clean suite showed
exactly the 4 known export failures (11-vs-10 row counts on three
export tests, 302-vs-200 on the browser entrypoint); no other suite
failures. Hand audit: 4 hostile paths + 6 hostile UAs + 1 query
line = 11 seed lines, but the `Evil "Quoted"` UA carries a raw `"`
inside a Combined quoted field, which the parser rightly rejects
as `malformed_line` (probed per-line: 10 accepted, 1 rejected with
reason `malformed_line`; old two-snapshot split separately
reproduced via public API as count=1/rows=2). The quoting hazard
now runs on valid single-quote bytes plus an NBSP-leading formula
row (12 accepted / 0 rejected, asserted in-seed with an
independent stored-row oracle). The 200 was TestClient following
the login redirect; the test now inspects the redirect with
`follow_redirects=False` (302 + `/login` location, no data or
metadata on the body).

Correction gates (each re-probed before fixing, then covered by
controlled tests — writers between preparation and streaming,
closed-resource assertions, no timing sleeps):

1. One owned export snapshot (`ExportStream` in
   `app/api/routes_export.py`): count, cap, metadata, cursor open
   and first-chunk prime share a single `BEGIN` on a dedicated
   read-only handle for BOTH Bearer [REDACTED] session downloads, before any
   byte streams (store/query failures map to safe 503/`request_id`
   or 400, never a 200 prefix). The sequential endpoint-thread to
   Starlette-worker handoff uses a per-connection
   `check_same_thread=False` (new opt-in kwarg on
   `app.db.database.connect`, default unchanged — no global
   switch, no `fetchall`). Cursor/connection close
   deterministically on EOF, renderer error, cancellation,
   explicit close without consumption and disconnect; post-header
   failures abort without `complete: true`.
2. Reproducibility metadata on BOTH transports: JSON gains the
   selected `sort` and `display_timezone`; CSV carries schema,
   site/source, UTC window, display timezone, sort, generated-at,
   exact count, coverage/quality and privacy in bounded ASCII-safe
   `X-Logcarve-Export-*` headers (non-default filters only,
   per-import `id`/`status` capped at 50 with an explicit
   `imports_truncated` flag — never silent truncation, never
   `error_summary`, never originals). The CSV body stays plain
   interoperable CSV (header row + records, no preamble); full
   filtered rows up to the documented 250000 cap (413 above) in
   bounded chunks; no limit/offset leakage (asserted absent).
3. Unicode-aware formula classifier: dangerous `=,+,-,@` detected
   after leading Unicode whitespace/control/format bytes (NUL, C0,
   DEL, NBSP, BOM, zero-width, separators), original text
   preserved behind the apostrophe; numerics/`None`/booleans keep
   safe-null/numeric semantics; no spreadsheet launched.
4. Exact integer metrics: `ComparisonMetricOut`
   current/previous/absolute_change are `int | float` end to end
   (service already exact); proven with SQLite int64-valid
   9007199254740993 plus small deltas against the shared service;
   ratios stay finite optional floats.
5. Fractional precision: security/comparison `window_seconds` is
   float seconds with an exact `window_seconds_us` companion
   (sub-second windows keep precise rates instead of 0/None);
   journey `duration_s` is float seconds with exact `duration_us`
   (1us journey reads 1us); whole-second behavior unchanged
   (old 3600/3599/0 assertions still green). No new timestamp
   formats.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused T3 `tests/integration/test_parity_t3.py` | PASS | 27 passed: 10 versioned routes (service equality, auth/scope/time negatives, AI-off/no-key), export rowcount/quoting/sentinels with independent oracle, JSON envelope + cursor equality, 1500-row exact streaming, negatives/cap, session-only browser entry (302 + Berlin display zone), int64-exact comparison, 0.5s/1.5s windows, 1us journey, single-snapshot freeze/retention, cap/lifecycle closes, post-header abort, both-format metadata, header cap flag — project `.venv`, Python 3.12.16 |
| New `tests/unit/test_export_cells.py` | PASS | 7 passed: ASCII leads, NUL/controls, Unicode whitespace, format bytes, verbatim preservation, benign text, safe-null/numerics |
| T2b preflight + old suites | PASS | `test_parity_t2b_preflight.py` 5 passed (incl. ruff UP012/format closeout); `test_parity_t2b.py`, `test_parity_t2b_corrections.py`, `test_traffic_api.py` 48 passed with new float shapes |
| Full `tests/unit tests/integration` clean | PASS | 777 passed, 2 skipped (loopback sockets unavailable in sandbox; pre-existing env category), 62s — `UV_CACHE_DIR=/tmp/uvcache uv run --locked pytest tests/unit tests/integration -q` |
| Full suite conflicting env | PASS | 777 passed, 2 skipped — same command with `AI_ENABLED=true LLM_WARN_AT_USD=999` ambient (no leakage) |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` + `config` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta (no new dependencies) |
| API offline/AI-off | PASS | Hermetic suite (Settings env cleared per-test; chat disabled, no model key) runs everything through TestClient with no provider transport; exports covered by the same offline path |
| e2e (Playwright/Chromium) | NOT RUN | Not in the T3a gate list; the one browser-touching change (display-timezone pass-through) is covered by TestClient session-download tests |
| Gitleaks pre-push scan | NOT RUN | No push authorized in this task; no secrets, real logs, keys or private paths added (synthetic TEST-NET fixtures only) |
| No-original-IP surface | PASS | Export columns, metadata, headers, errors and session downloads carry pseudonyms + truncated agents only; originals never leave the store |

Acceptance impact: PAR-07 API/export (T3a) only — routes, both
download entries, snapshot/cap/metadata/formula/exactness/
precision corrections with actual checks above. T3b (assistant,
tools, stdlib-client expansion), full UI, follow/rotation,
GeoIP and PAR-08+ stay unclaimed. Stopping for independent
reinspection.

## 2026-11-01 — Parity T2b correction A-H (before T3, shared layer)

Owner-authorized LogWerk parity T2b correction on
`feature/logwerk-parity-2026-11-01`, exact model
`muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents, no new approval loop, no
parent private files/keys/logs, product calls, Docker, pushes, main
or deployment. All code/tests by the implementer. Public/synthetic
data only; the immutable 120-row fixtures, HMAC/core identities,
auth/usage/consumed allowance and the 77-rule bot catalog stay
unchanged (asserted untouched in-test). Prior commits preserved, no
amend. Coordinator probes A-H were reproduced on the frozen T2b
commit first (throwaway `/tmp` probes: right-at-equality False,
`no such column` on 8 metadata filters, 102 SELECTs for 100
offenders, 500-errors 0, empty-current comparable True, GET-vs-POST
accepted, no per-side filters), then fixed. Definitions corrected
in `docs/logwerk-parity-metrics.md` (asymmetric edges, microsecond
comparisons, group totals, >=400 errors, strict selectors with
empty-side honesty, burst/sequence evidence, opaque ID lookup). No
HTTP/UI/export wiring; old bot-conflict/legacy finding counts
intact.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t2b_corrections.py` | PASS | 21 passed: A (right-partial at equality + expanded-window control proving continuation, left-complete asymmetry), B (17 metadata/content filters on list/timeline/entries with unchanged IDs/starts/entries + no silent ignoring), C (6 SELECTs for 1 vs 100 offenders, groups-vs-paths multi-status incl. legacy all-status scope), D (200/304/401/403/500 exact + 4xx/5xx split + overlapping-rule honesty vs unique events), E (empty current/both empty unavailable, empty previous keeps zero_baseline, running-import unavailable, 5 selector mismatches rejected, paging/window-only differences compare), F (spread-vs-burst peaks 1 vs 6 with equal averages + window_seconds, bounded 10/16 sequence with gaps + benign rows + outside-window exclusion), G (epoch-micros exactness, offset normalization, naive rejection, SQLite scalar, 1800s +/-1us grouping/edges, identical instants), H (ID roundtrip == direct timeline for all 5 key shapes incl. NULL vs empty UA + long UA, same-start distinction, offset-spelling resolution, tampered/out-of-scope KeyError) — project `.venv`, Python 3.12 |
| Corrected `tests/integration/test_parity_t2b.py` | PASS | Symmetric exact-right-complete expectation replaced with the proven asymmetric rule (right-partial at equality + control reference); all other T2b cases unmodified and passing |
| Full `tests/unit tests/integration` | PASS | 738 passed, 2 skipped (loopback sockets unavailable in sandbox; same pre-existing env category as frozen T2b) |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` + `config` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta (no new dependencies) |
| e2e (Playwright/Chromium) | NOT RUN | No browser, HTTP, UI or export changes in this correction (shared analytics layer only); no e2e file references the changed shapes |
| Gitleaks pre-push scan | NOT RUN | No push authorized in this task; no secrets, real logs, keys or private paths added (synthetic TEST-NET fixtures only) |
| No-original-IP surface | PASS | Journeys/timelines/ID resolution/offenders/sequences carry pseudonyms + truncated agents only; resolution returns keys, never addresses |

Acceptance impact: PAR-05/PAR-06/PAR-08 stay at the shared
service/query layer with corrected definitions; API/export wiring
stays T3 and admin UI stays T4, not claimed. Stopping for
independent review.

## 2026-11-01 — Parity T2b journeys/security/comparison (E/F/H, shared layer)

Authorized LogWerk parity build on `feature/logwerk-parity-2026-11-01`,
exact model `muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents. Public/synthetic checkout only:
no parent private files/keys/real logs/product calls/Docker/push/main/deployment.
All code/tests by the implementer. No UI import or translations; no
original-IP joins/projections; legacy HMAC/IDs/auth/usage/allowance,
the 120-row fixture and the 77 bot rules with the conservative
conflicting-bot detector preserved. Metric definitions and provenance:
`docs/logwerk-parity-metrics.md` (E/F/H sections added).

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t2b.py` | PASS | 19 passed: journeys (gap equality 29m59s/30m/30m1s, identical-ts stability, filter-proof starts, edge partials incl. exact-gap-complete, paging/sorts, bounded timelines, entry agreement), security (5050-path beyond-cap exactness, 401/403 rate + benign controls, breadth threshold, traversal no-decode spellings, line-vs-event, preserved counts), comparison (exact deltas, zero/empty baselines, unequal-scope rejection, insufficient coverage) — project `.venv`, Python 3.12 |
| Full `tests/unit tests/integration` | PASS | 717 passed, 2 skipped (loopback sockets unavailable in sandbox; pre-existing env category) |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` + `config` (one COUNT-ELSE-0 support-link regression and one legacy-sample regression caught by existing tests and fixed before commit) |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta (no new dependencies) |
| Bot catalog / HMAC / 120-row fixture | PASS | Untouched: new tests generate tmp fixtures only; 77-rule count asserted in-test; old security IDs/versions byte-identical |
| No-original-IP surface | PASS | Journeys/timelines/entries/offenders carry pseudonyms + truncated agents only; rejected lines reported at line level with code vocabulary, never as events |

Acceptance impact: PAR-05/PAR-06 implemented at the shared
service/query layer (deterministic, parameterized, bounded SQL;
`total_groups` exact, samples bounded with shown/total/truncated;
401 = challenge / 304 = validation wording; ratios unavailable, never
infinite). PAR-08 comparison windows implemented as shared-layer
validation + helpers; follow/rotation, saved views and refresh stay
with T3/T5. Actual API/export wiring stays T3 and full admin UI stays
T4, not claimed complete here. Stopping for independent review.

## 2026-11-01 — Stage B3bcb915 browser-test maintenance (9 stale expectations, test-only)

Owner-authorized TEST CORRECTION ONLY on `feature/owner-ux-review-2026-11-01`
after `ffaf737`, exact model `muse-spark-1.3-contributor`/medium/Contributor ON;
sandbox + approval ON, no agents/product calls/screenshots/secrets/Docker/
push/main/deploy. Implements the maintained-test corrections enumerated in the
appended section "Actual protected Chromium full diagnostic at Stage B3bcb915"
of `artifacts/task-inputs/owner-ux-b-review.md` (28 tests: 19 PASS / 9 FAIL).
No app/config/asset/fixture change: no confirmed application defect found, so
nothing was reported for coordinator review and scope stayed tests + docs.

Corrections (all in `tests/e2e`, semantic assertions preserved/strengthened):

- Ambiguous navigation (fail 1): `test_dashboard::test_narrow_menu_overlay_without_overflow`
  and two `test_slice_b` sidebar uses now name "Main navigation" explicitly
  (Quick views renders a second nav); overlay-geometry/keyboard checks kept.
- Status identity (fail 2): new `_status_code()` in `test_dashboard`/`test_slice_b`
  parses numeric codes from `200 · OK` labels; table/JSON/live-chart-axis codes
  are compared AND human phrases asserted (middle-dot separator, OK / Not Found
  / Internal Server Error) — no dropped comparison. Slice B additionally captures
  live chart axis labels.
- Starters 8→9 (fail 3): both dashboard Ask tests expect 9; the new Security
  "Help me create firewall rules" starter asserts its MANUAL-REVIEW prompt fills
  the input only (no send, status hidden, answer empty); disabled-Send, scope and
  error assertions preserved.
- Status select (fail 4): `test_errors_apply_preserves_matchers_source_and_nav`
  reads the native `#f-status` select value instead of the removed
  `input[name=status]`; Apply/URL/nav/scope assertions preserved.
- Details binding (fail 5): `test_requests_sort_headers_and_details` rebinds the
  SAME toggle by its stable aria-controls panel id (the accessible name flips
  Show→Hide on open); same-button/panel/keyboard-close/Apply/paging-reuse kept.
- Explorer columns (fail 6): `test_explorer_columns_sanitized_and_timezone_aware`
  asserts the actual 8-column header semantics, reads CET display + UTC title
  through the Time-column index, toggles the Time sort header oldest/newest with
  ISO-title ordering, and checks expanded details (User-Agent, Referring domain,
  Rule, timing-unavailable) with the hostile UA escaped.
- Asian zone (fail 7): JST is read from the Time semantic column instead of the
  first (Client) cell; narrow-overlay/Tokyo/URL/nav/reload checks preserved.
- New `test_berlin_option_labels_follow_dst_across_apply`: winter Apply option
  label UTC+01:00 → summer UTC+02:00 on the same selected Europe/Berlin option,
  exactly one `#f-tz` control, and a failed Apply keeps the labels (deliberate
  400 recorded as exactly 2 console errors, never suppressed).

Actual results (project `.venv`, same session):

| Check | Result | Evidence |
| --- | --- | --- |
| `pytest tests/e2e --collect-only` | PASS | 29 collected (28 + 1 new Berlin test) |
| `ruff check tests/e2e/` | PASS | All checks passed |
| `ruff format --check tests/e2e/` | PASS | 6 files already formatted (3 reformatted by the check run) |
| `pytest tests/e2e` execution (this sandbox) | BLOCKED | Protections ON; sandbox launch never retried per authorization; coordinator runs `uv run --locked pytest tests/e2e -q` outside |
| Full unit/integration suites | NOT RUN | Test-only change; coordinator runs the final full suite |
| Real product model/provider calls | NOT RUN | No product calls made |

## 2026-11-01 — Slice C targeted performance gate: batched per-client path sampling (plan)

Bounded optimization only, on clean `ca491c2` (`feature/traffic-analytics`).
Independent 100k profile: filtered Overview 8.825s, `service.security_findings`
7.950s, 100× `sample_paths_for_client` scans 7.641s with 14.27M
`classify_ua` calls. Fix: one shared parameterized batched
top-5-per-client `(path, status, hits)` helper over the full scoped filter,
using SQLite window ranking (`ROW_NUMBER() PARTITION BY client_pseudonym
ORDER BY hits DESC, path ASC, status ASC`), bounded to 100 clients / 500
returned rows, empty set returns without a query. No schema/index migration,
no writes, no cross-request cache, no new dependency, no API/model contract
change. Original all-status sampling semantics kept exactly: every base
filter (site/source/window/method/status/class/path/referrer/search/
traffic/bot) applies before grouping; per-client order and findings
order/caps unchanged. Tests: hand-counted ties, cross-site/source
separation, window/time bounds, status/class narrowing, filter no-widening,
empty and cap cases, plus old-vs-new equality.

Results 2026-11-01 (same session, clean tree before commit): new
`tests/integration/test_security_batch_sampling.py` (12 tests) covers
per-candidate old-vs-new equality, tie order, all-status semantics
(200/500 rows stay sampled), per-client top-5 cap, status/class/path/
search/method narrowing, in/out-of-window bounds, cross-site isolation,
cross-source narrowing, classifier (`claimed_bot`) scoping, empty-list
zero-statement cheap path, 101-client/500-row bounds with exactly 1 traced
SQL statement, findings counts/order/samples, and empty-window findings.
Focused + existing suites
(`test_security_batch_sampling`, `test_analytics`, `test_api`,
`test_demo_slice_c`, `test_t8_preparation`, `test_web_partb`,
`unit/test_ai_tools`): 106 passed, exit 0. `ruff check .` PASS,
`ruff format --check .` PASS (152 files) after formatting the new test
file. Full unit/integration, browser/candidate and 100k benchmark reruns
are coordinator-owned (NOT RUN here).

## 2026-11-01 — Slice C fixture-quality correction (browser/SEO breadth, undeployed)

Owner-authorized bounded correction on clean `f740e6f`
(`feature/traffic-analytics`). Sole writer, exact model
`muse-spark-1.3-contributor`/medium/Contributor ON; sandbox + approval ON, no
agents/calls/push/main/private-parent access. Synthetic fixtures only; T8
fixture byte-identical (`d765393f…ebeb65`, 30 rows). No behavior, schema,
dependency, runtime, credential or ledger changes.

The 90-row rich fixture used one generic `Mozilla/5.0 (X11; Linux x86_64)
synthetic/1.0` UA for all 27 browser-like rows (browser chart entirely
Other with the 21 legacy rows) and lacked stylesheet/script/font/media
samples plus an active SEO bot. Corrected 10 lines per day, in existing
row order, with all statuses/methods/bytes/client addresses/times/referers
unchanged: Chrome-Windows `/`, Firefox-Linux `/assets/app.css`, Safari-macOS
`/assets/app.js`, Chrome-Windows `POST /api/search`, Edge-Windows
`/images/logo.svg`, Safari-iOS `/fonts/site.woff2` (404 kept),
Firefox-Linux `/video/intro.mp4` (301 kept), Safari-macOS `POST /contact`,
Chrome-Android `/blog/old-slug`; one CCBot row per day now claims synthetic
AhrefsBot (`bot-seo-ahrefs`, still claimed_bot). Per-day browser families
Chrome3/Firefox2/Safari3/Edge1, OS Windows3/Linux2/macOS2/iOS1/Android1;
combined families Chrome9/Firefox6/Safari9/Edge3 + 21 legacy Other, OS
Windows9/Linux27 (21 legacy X11/Linux + 6 rich)/macOS6/iOS3/Android3;
resource style/script/font/media 3 each, image 6 (new SVG 3 + favicon 3);
totals exactly 120 rows / 127744 bytes, traffic 48/45/18/9, T8 rows 30.

- New rich SHA `b9479a8e…52ca45f` pinned in `probe_store.py`,
  `verify_candidate.sh`, `smoke_demo.sh`,
  `tests/fixtures/expected/demo_slice_c.json` (named_bots
  `bot-ai-ccbot`→`bot-seo-ahrefs` 3 combined / 1 per day, per-day and
  combined path counts only); T8 pins untouched. First C rich hash never
  deployed; original T8 never changed.
- New tests in `test_demo_slice_c.py`: static per-day spec check (path
  order, status/byte sequences, brand/OS markers, Ahrefs 1/day, no CCBot
  or generic UA left) and product-agreement check (browser/resource/SEO
  breadth with exact 120/127744, classes 48/45/18/9, T8 rows 30).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/integration/test_demo_slice_c.py tests/integration/test_demo_probe.py` | PASS | 22 passed (14 Slice C + 8 probe), `.venv/bin/python -m pytest` |
| `ruff check .` | PASS | All checks passed |
| `ruff format --check .` | PASS | 151 files already formatted |
| `uv lock --check` (`UV_CACHE_DIR=/tmp/uv-cache`) | PASS | 40 packages, lockfile current, no new dependency |
| Full unit/integration suite | NOT RUN | Coordinator performs the final clean/conflicting full suites |
| Browser/Docker/candidate/smoke | NOT RUN | Coordinator-owned (sandbox has no socket; never attempted) |

Acceptance impact: demo dataset now exercises the accepted browser/OS,
resource-kind and SEO analyses before deployment; probe/seeder/upgrade/
replay/refusal logic and all state-safety guarantees unchanged.

## 2026-11-01 — Slice C delivery + B legacy-test update (independent runtime verification pending)

Owner-authorized Slice C (`artifacts/task-inputs/slice-c-delivery.md`) on clean
`36eb09f`, branch `feature/traffic-analytics`. Sole Muse writer, exact model
`muse-spark-1.3-contributor`/medium/Contributor ON; sandbox + approval ON, no
agents. Synthetic fixtures only; T8 fixture byte-identical
(`d765393f…ebeb65`, 30 rows). No database/usage reset, no push/main change,
no new dependency, no Docker-socket access, no parent-runtime/secret reads.
No product model/provider calls in any PRODUCT test below (Muse coding-model
usage is separate and never touches product paths).

Slice B legacy-test update (from `slice-b-final-independent-review.md`):
`tests/e2e/test_dashboard.py::test_errors_apply_preserves_matchers_source_and_nav`
no longer expects `status=404` to disappear on sidebar Security navigation —
`status` is a global matcher (`MATCHER_KEYS`, `app/web/routes.py`), so
preservation is the accepted behavior. Product behavior untouched; only the
outdated expectation/comment changed.

- New `tests/integration/test_nav_status_matcher.py` (1 test): Errors page
  sidebar Security href preserves `status=404` + source + window, and the
  followed link renders 200. PASS — server-side positive evidence for the
  updated browser expectation (browser re-run is coordinator-owned).
- New `tests/fixtures/combined/demo_rich_29_31oct.txt` (90 rows, 30/30/30
  over 29–31 Oct 2026, `b9479a8e…52ca45f`): every UA verified per-rule
  against the classifier before pinning (google/gpt/claude/bing/ahrefs,
  curl/python/uptimerobot/suspected, labeled Chrome/Firefox/Safari/Edge
  browser families on brand/OS-marked synthetic UAs, `-` unknown).
- New `tests/fixtures/expected/demo_slice_c.json`: hand-derived with
  awk/grep/sort (never the product parser) — combined 120 rows,
  200×86/301×3/404×28/500×3, GET×107/POST×9/HEAD×3/OPTIONS×1,
  claimed×45/automation×18/browser×48/unknown×9, bytes 127744, 44 distinct
  clients. One byte-sum scare (`597238`) was the author's own probe snippet
  summing `byte_offset` instead of `bytes`; product data always agreed with
  the independent awk sum (127744).
- `scripts/demo/probe_store.py`: pins both digests; FRESH / PARTIAL (empty,
  legacy T8-only upgrade, rich-only, no-admin, interrupted-with-known-fingerprints)
  / SEEDED (30+90, both fingerprints, admin present) / FOREIGN (drift, unknown
  site/source/rows/fingerprint, unresumed unknown-provenance failures). A failed
  attempt is superseded only by a clean completed import of the same source
  bytes, so interrupted-then-resumed stores converge instead of sticking.
  Two genuine probe strictness gaps found by the new tests and fixed:
  a foreign site with zero rows stayed PARTIAL (now FOREIGN), and a failed
  import row blocked SEEDED forever (now superseded on resume).
- `scripts/demo/seed.sh`: imports both fixtures under unchanged
  `example-combined`, replay-zero `(0,30)` + `(0,90)`, token/admin/history/
  spend preservation kept, FOREIGN refused.
- `scripts/demo/verify_candidate.sh` (new, tracked): isolated candidate on
  unique project `logcarve-demo-candidate`, loopback 8091, temp owned
  runtime, `git archive HEAD` build, both digest pins, SEEDED-120 +
  replay-zero + restart proof, teardown of owned resources only.
- `docker-compose.demo.yml` (+rich mount), `scripts/demo/lib.sh`,
  `docs/demo.md`, `docs/demo-script-3min.md`: combined-window URL
  (26 Oct–01 Nov), 120-row narration.
- `scripts/smoke_demo.sh` + `scripts/smoke_offline_probe.py`: offline proof
  now covers the combined dataset (30+90 imports, 120-row client summary,
  120-row restore).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/integration/test_demo_slice_c.py test_demo_probe.py test_nav_status_matcher.py` | PASS | 21 passed (12 Slice C + 8 probe + 1 nav) |
| Full `pytest tests/unit tests/integration` (clean env) | PASS | 408 passed, 2 skipped (pre-existing loopback-bind skips) |
| `ruff check .` | PASS | All checks passed |
| `ruff format --check .` | PASS | 151 files already formatted |
| `uv lock --check` (`UV_CACHE_DIR=/tmp/uv-cache`) | PASS | 40 packages, lockfile current, no new dependency |
| `npm run build` + `check:external` | PASS | Rebuilt clean; no fetch-vector external references (exit 0) |
| `pytest tests/e2e --collect-only` | PASS | 22 collected |
| Gitleaks 8.30.1, fully redacted, all 17 changed/new files | PASS | Exit 0 on every file; no finding (tracked-file scan; full-history scan repeats at release) |
| `pytest tests/e2e` execution (this sandbox) | BLOCKED | Chromium cannot launch in this macOS shell sandbox (recorded protection); coordinator runs outside |
| Docker/candidate/smoke execution | BLOCKED | No socket access from this sandbox; never attempted; coordinator owns runtime/backup/rollback/testing |
| Linux x86-64 | NOT RUN | ARM64 only; x86 distinction preserved |
| Real product model/provider calls | NOT RUN | AI-off posture throughout; exhausted allowance untouched |

Acceptance impact: ING-04 (additive replay/idempotent upgrade, interruption
convergence, foreign refusal), DB-01 (restart persistence, preserved history,
no reset/delete/recreate), OPS-02/03 (candidate + offline-smoke procedures
ready for coordinator execution; 100k benchmark already recorded, typical
whole-page run is coordinator-owned), QA-01 (independent review still
required; B legacy update keeps the accepted behavior). Deferred gzip/custom
formats, GeoIP, sessions, live ingestion, export/import UX unchanged — no
LogWerk parity claimed. Ruff note: never pass `tests/fixtures/expected/*.json`
as explicit `ruff format` paths — this ruff emits trailing commas into JSON
(invalid); directory-wide `ruff format --check .` leaves the single-line
fixtures alone.

## 2026-11-01 — Slice B correction (independent-review gaps closed, reinspection pending)

Coding delivery closing every accepted gap from `artifacts/task-inputs/slice-b-independent-review.md`
and `slice-b-scope-check.md`. Directly observed in this session unless noted.

- Full suite: 393 PASS + 2 sandbox loopback skips
  (`.venv/bin/python -m pytest tests/unit tests/integration -q`).
- New `tests/integration/test_web_slice_b2.py` (9 tests): timeline
  errors/bytes datasets; paths visible sort + bytes column with bogus-sort
  400; heatmap 168 leveled cells + legend; explorer bytes/referrer/rule
  columns, Berlin/UTC time duality, attack-UA escaping; bot groups exact
  vs table totals and pagination-independent; visible method/status/
  referrer controls, search maxlength 128, no duplicate hidden names; Ask
  scope attributes; settings back-roundtrip with matchers.
- Updated contract-change tests: `test_active_nav_keeps_full_filters`,
  `test_filter_apply_preserves_scope` (visible status control),
  `test_matchers_travel_with_shared_window_state` (renamed; matchers are
  shared nav state now, the explicitly accepted correction).
- New `tests/e2e/test_slice_b.py` (7 tests, 14-row hand-counted fixture):
  Chart.js values vs JSON vs tables, nav/settings/Ask preservation via
  real interaction + captured Ask payload, grouping vs paging, sorts,
  heatmap colors both themes, explorer columns/sanitization, 390px both
  themes, no off-origin requests. Authored, collection-verified (22 e2e
  collected), execution BLOCKED in this sandbox (see below).
- Gates: `ruff check` clean; `ruff format` clean after formatting touched
  files; `npm run build` + `check:external` clean (heat CSS in built
  bundle, JS in sync); `uv lock --check` BLOCKED (sandbox denies uv cache
  writes; `pyproject.toml`/`uv.lock` untouched, no new dependency).
- Browser execution BLOCKED: Chromium headless-shell fails to launch
  inside this macOS shell sandbox (`MachPortRendezvousServer ... Permission
  denied`); protections left ON per authorization. Coordinator runs
  `uv run --locked pytest tests/e2e -q` outside the sandbox.
- Privacy/egress/cost gates unchanged: no new model calls, no provider
  traffic, shared analytics layer only, synthetic fixtures only.

## 2026-11-01 — Slice B final correction B (reinspection pending)

Prior independent protected-Chromium run, honestly recorded: `tests/e2e/test_slice_b.py`
6 PASS + 1 FAIL (`test_timeline_charts_match_tables_and_json`: Chart.js
request/error/bytes-vs-JSON asserts passed, then `int(r[1])` read `""` from
the timeline table `innerText` immediately after opening the native
`details`/collapse; the later failure screenshot showed visible numeric rows).
All 9 `tests/integration/test_web_slice_b2.py` tests PASS in that run.

Diagnosis (readiness, not rendering): daisyUI animates the collapse open, so
`innerText` stays `""` until the rows paint; the immediate post-click
`evaluate` raced that transition. The data was always in the DOM and the
product rendering was correct, so no product change was made for this.

Exact changes on `d891bb2` (no scope expansion, no unrelated fixes):
- `tests/e2e/test_slice_b.py`: after each `summary.click()`, a deterministic
  `wait_for_function` waits for the opened table's first data cell to be
  populated (no sleep, no skipped blank rows, no weakened assertions); every
  timeline cell (label/requests/errors/bytes) is now verified against the
  embedded JSON and live Chart.js datasets; hand-counted fixture totals
  14 requests / 3 errors / 6093 known bytes replace the weak `bytes>0`
  assertion; the already-opened status table is verified against its JSON,
  live chart and a 14-request total.
- `app/web/routes.py`: heatmap quantization is now ceiling scaling with level
  0 reserved for zero (`0 if value == 0 else min(4, -(-value * 4 // peak))`),
  so positive cells below 25% of the peak no longer wear the no-request shade.
  Numeric counts, CSP-safe classes and local styles are unchanged.
- `tests/integration/test_web_slice_b2.py`: new
  `test_heatmap_low_positive_never_level_zero` (larger peak required, a
  low-positive cell below 25% of peak required, `level == "0"` iff count is
  zero). It FAILS pre-fix (`1 requests must never use the no-request shade`)
  and passes post-fix. Both-theme computed-color proof stays in the e2e test.

Directly observed in this session (synthetic data only):
- `pytest tests/integration/test_web_slice_b2.py`: 10/10 PASS.
- `pytest tests/unit tests/integration`: 394 passed + 2 sandbox loopback skips.
- `ruff check .` clean (one RUF015 in the new e2e code fixed as suggested);
  `ruff format --check .` clean; `npm run build` + `check:external` clean.
- `uv lock --check` BLOCKED (sandbox denies uv cache writes;
  `pyproject.toml`/`uv.lock` untouched, no new dependency).
- E2E execution BLOCKED in this sandbox: project-local
  `chromium_headless_shell-1248` exists under `artifacts/`, but launch fails
  here (`Target page, context or browser has been closed`); the file collects
  cleanly (7 tests). Coordinator reruns
  `uv run --locked pytest tests/e2e -q` outside the sandbox.

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

## 2026-11-01 — Slice A traffic analysis backend (analytics completion)

Owner-authorized Slice A implementation; no merge to `main`, push,
deployment or product calls. One lead, no agents. `npm run build`
prerequisite completed (tracked `app/web/static/app.css` banner refresh;
`app/web/static/js/` remains ignored build output).

- Full locked suite: 378 passed, 2 skipped (loopback sockets unavailable
  in sandbox: `test_external_client.py`), 0 failed.
- Gates: `ruff check` clean, `ruff format --check` clean,
  `uv lock --check` clean (no dependency changes).
- New coverage: 52-UA shared vectors (`tests/fixtures/expected/ua_vectors.json`)
  with SQL-vs-Python agreement; 30-row hand-counted traffic fixture
  (breakdown sums, zero-filled buckets, sorts/paging, bot detail,
  explorer sanitization/search, browsers/resources/heatmap/clients,
  >5000 distinct-UA exact counts); 10-row API fixture (endpoints,
  unknown/contradictory selectors, route-level bot-conflict 400 and
  unknown-bot 404, cross-site denial, fractional/unknown tz 400);
  trusted-scope tests (selected-parent enforcement, valid narrowing when
  unset, unknown-selector and sensitive-search rejection, exact replay,
  tool/service aggregate equality, chat-route scope over hostile args).
- Scale note (provisional, not a guarantee): independent runner measured
  100k rows / 100k distinct UAs with 25k exact per traffic bucket, import
  2.204 s, filtered summary ~5.36–5.46 s, bot table 2.393 s, peak RSS
  62.38 MiB. Repeated-UA latency and app-scale profiling stay Slice C work.
- Pre-existing/environmental, unchanged by Slice A: `test_t8...guard`
  needed built assets (resolved by the prerequisite build); 2 loopback
  skips; browser/e2e execution stays with the independent local runner.

## 2026-11-01 — Slice A independent review (ed24256)

Independent coordinator review on committed candidate ed24256
(feature/traffic-analytics), clean tree confirmed. No blocking backend
finding; UI/demo/release gates explicitly not closed.

- Own hand-counted 28-row synthetic API probe: 53/53 PASS, zero model
  calls (buckets 6/15/5/2, requests 28, 4xx 8, 5xx 3, bytes 3485,
  measured 27; priority, literal search/privacy, bot-sort,
  conflict/selector rejection, all new endpoints, foreign-source denial,
  unchanged source).
- Maintained focused tests: 41 PASS, no skips (classification, traffic
  services/API, hostile assistant scope, valid narrowing/replay, both
  external-client real loopback cases — resolving the 2 sandbox-only
  skips from the coding run).
- Coding full suite observed 378 PASS + 2 sandbox skips, lint/format/lock
  clean.
- Nonblocking follow-ups carried into Slice B: stale root
  scaffold/licensing status, visibly bounded sample labels, whole-page
  latency as a C gate with no performance guarantee.

## 2026-11-01 — Slice B implementation (uncommitted → commit, independent review pending)

Coding session delivery for Slice B (rich charts, traffic/bot/filter
controls, sortable bot drilldowns, sanitized request explorer, global
URL/Ask state). Directly observed in this session unless noted.

- Full suite: 384 PASS + 2 sandbox loopback skips
  (`uv run --frozen pytest tests/unit tests/integration -q`), after
  updating one stale Slice A matchers-shape expectation in
  `test_t8_preparation.py` (matchers now carry the full trusted selector
  contract) and one stale crawlers-view UI assertion.
- New `tests/integration/test_web_slice_b.py` (7 tests): conjunctive
  robots/sitemap cards under `path_prefix=/docs/` and `/no-match`;
  `traffic=error` rejected with 400; every data page
  (/, /security, /crawlers, /errors, /requests, /ask) 200 under
  `traffic=claimed_bot` and bot filter with unknown-bot 400; overview
  panels + filter controls render; crawler/request sort validation.
- Gates: `ruff check`, `ruff format --check`, `uv lock --check` clean;
  `npm run build` completed (tracked `app/web/static/app.css` refresh).
- Early-review cases closed: scoped cards use conjunctive
  `scoped_path_count`; no `traffic="error"` bucket (errors stay
  orthogonal status criteria); all data-page service reads pass the
  versioned rules; paging carries sort; Jinja `range` shadowing fixed.
- NOT RUN here: browser/e2e (loopback skips in sandbox; coordinator
  runs Playwright incl. extended nav roundtrip with /requests).
- Coverage: ANA-05, API-05 (service layer; external API unchanged),
  UI-05 implementation done; independent browser review before C.

## 2026-11-01 — Selector error privacy correction (feature/traffic-analytics)

Bounded fix for the independently reproduced selector reflection: unknown
bot/provider/purpose values were embedded in the `InvestigationError`
message and echoed by the authenticated chat 400. Synthetic repro only
(`synthetic-selector-private-sentinel`, no DB or provider use); pre-fix
`str(exc)` contained the sentinel for all three selector kinds.

- Fix (`app/ai/service.py`): selector `ValueError` now maps to the fixed
  message `Unknown or contradictory selector.` Internal chaining
  (`from exc`) retained; `invalid_request`/HTTP 400 behavior unchanged.
  No provider called, no model-history/cost changes.
- Regressions (`tests/integration/test_assistant_corrections.py`):
  parametrized bot/provider/purpose sentinel nonreflection (fixed text,
  chained `ValueError`, zero fake-provider calls, zero budget spend) plus
  an authenticated chat 400 case asserting body/header `request_id`
  parity and full-body sentinel nonreflection.
- Observed: 4 new tests PASS; 61 PASS across corrections, assistant
  scope, assistant and classification suites; full corrections file
  24 PASS; `ruff check` and `ruff format --check` clean.

## 2026-11-01 — Analytics completion independent verification (reported, append-only)

Independent local runner evidence for clean source `e81d2d0` on
`feature/traffic-analytics`, exactly as supplied in
`artifacts/task-inputs/final-verification-evidence.md`. This section only
transcribes the runner's reported outcome; the documentation writer did
not re-execute coordinator checks, read private runtime or credentials,
make provider/product calls, or change code, tests, fixtures,
configuration or assets. Historical PASS/FAIL/BLOCKED/NOT RUN records
above are preserved unchanged.

- Full locked unit+integration: 428 passed, 0 skipped in a clean
  environment, and 428 passed, 0 skipped with `AI_ENABLED=true
  LLM_WARN_AT_USD=999`.
- Maintained protected Chromium E2E: 22 passed, 0 skipped. Actual
  Chart.js datasets/tables, new filters/nav/settings/Ask capture,
  groups/sort/paging, heatmap and explorer, both themes at 390px, no
  off-origin requests or errors.
- Own independent 28-row API probe: 53/53 passed on the final
  application source.
- Ruff check + format check: 152 files clean; `uv lock --check` 40
  packages PASS; asset build and no-external-references check PASS.
- Fully redacted Gitleaks tracked-export directory and full 10-commit
  public history scans: exit 1 only for the known
  `technical-spec.md:787` cost-heading false positive (history
  occurrence in `b52a9fb`). No broad allowlist, no new finding.
- Docker Compose candidate: 8 PASS / 0 FAIL from a fresh tracked
  export, 120 rows, old 30 / new 90, replay 0/30 + 0/90, restart
  persistence, full owned teardown.
- Docker internal-network offline smoke: 24 PASS / 0 FAIL, 120 rows,
  authenticated API with AI off, no model key and no Internet, backup /
  isolated restore / retention, source immutability, no leftover owned
  containers/networks/volumes.
- Built-image browser matrix: 32 PASS on the isolated candidate; same
  32 PASS on the actual persistent localhost 8080 demo after update
  (8 routes, light/dark, 1440px/390px), no console errors, off-origin
  or failed responses. Real filter Apply and sidebar keep 45 claimed
  requests; the named GPT filter selects 16.
- Independent text-only fixture recount (no product imports): 120 rows,
  127744 known bytes, 44 distinct source addresses before HMAC; traffic
  buckets browser-like 48 / claimed bot 45 / other automation 18 /
  unknown 9; status 86x200, 3x301, 28x404, 3x500; paths, methods,
  referrer, day, rule counts match goldens. Immutable T8 SHA
  `d765393f…ebeb65`; final rich SHA `b9479a8e…52ca45f`.
- 100k repeated-UA whole-page profile (same seeded source/order before
  and after the targeted N+1 fix; single observations, not percentiles
  or guarantees): 100000 lines to 98969 accepted / 1031 intentional
  rejects, import 1.7969 s; Overview all 1.2911 s, claimed 2.7859 s
  (before 2.3153 / 8.8252 s); Crawlers all 1.0946 s / claimed
  1.2778 s; Requests all 0.2705 s / claimed 0.6873 s. 19855 Googlebot
  rows independently counted from source. SQLite integrity ok, source
  unchanged, DB+sidecars 45916160 bytes, cumulative runner peak RSS
  165.94 MiB. Hardware: Apple M5 Pro, 18 logical CPUs, 48 GiB RAM,
  macOS 27.0.1 arm64, Python 3.12.16. The profile identified
  100-per-client path scans; one bounded batched query replaced them
  with the same evidence/count/order/caps and every scope selector. No
  schema, dependency, cache, write-on-read change.
- Local demo outcome: existing canonical project folder updated on a
  separate local branch, previous branch/history preserved, main
  unchanged, NO GitHub push. The entire tracked integration tree
  matched the tested public candidate before this documentation
  closeout. The running demo uses the EXACT tested image (not an
  unverified host build), UID 10001, loopback `127.0.0.1:8080`, AI off,
  key empty, read-only sources. Online backup retained 0600 plus the
  old image rollback ref. Upgrade 30 to 120 succeeded: all 30 legacy
  rows byte-identical; credentials, users/tokens, preexisting sessions
  and usage state preserved; schema 4 unchanged; SQLite integrity ok.
  The original 26–29 Oct exclusive window still returns 30. The
  existing token works; the actual stdlib client succeeds on all 3
  supported replies. No new product model/provider calls, no allowance
  reset, no real logs. Muse coding-model usage is separate and not
  covered by product app caps. Temporary candidate credential/runtime
  directories and all owned test resources were removed; the
  persistent 8080 demo remains running.
- Platform limit: actual Docker Linux ARM64 only. Linux x86-64 and
  standalone Linux host install NOT RUN; no full release, hackathon or
  all-project QA approval is claimed. UI-05 / ANA-04 / ANA-05 /
  API-05 local gates are satisfied. Deferred: gzip, custom formats,
  live ingestion, GeoIP/sessions, export/import UX.
- Fixed demo entry window for recording:
  `http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined`.

Acceptance impact: UI-05, ANA-04/05 and API-05 local gates are satisfied
at `e81d2d0` per the independent runner; deferred scope and the
incomplete three-case AI demonstration are unchanged. No paid replay or
new product calls were made for this documentation closeout.

## 2026-11-01 — Stage A display-timezone catalogue (acceptance-readiness plan)

Owner-authorized bounded work on clean `5ff5f22`, branch
`feature/acceptance-polish-2026-11-01`. Sole writer, exact model
`muse-spark-1.3-contributor`/medium, Contributor ON. Public source +
synthetic fixtures only; sandbox, approval judge, CSP and product
Standard fail-closed egress unchanged. No provider/product calls, pushes,
`main` merge, production deployment, extra dependencies or unrelated
features. No parent/private runtime, secrets, traces, tokens, real usage
or model-key inspection.

Change: the hardcoded UTC/Berlin pair became the cached server-installed
IANA catalogue (`app/web/timezones.py`: `available_timezones` once per
process; every supported key retained and validated server-side plus a
`ZoneInfo` construction check). Stable order: validated configured
default first, UTC next, then regions alphabetically with zone/city names
alphabetical inside each region; readable labels (underscores to spaces),
exact IANA values, no duplicates, native `<select>` kept. Precedence:
explicit valid `tz` wins; blank uses validated `DEFAULT_TIMEZONE`
(demo: `Europe/Berlin`); only an exact installed key from operator `TZ`
counts as a local server name — abbreviations/offsets are never guessed,
anything unusable falls back to UTC. Unknown/filesystem-style zones fail
safe (`error.bad_params`). UTC storage, UTC time bounds, existing
query roundtrip/nav/settings/evidence URLs and the public API UTC contract
are untouched. `Settings.default_timezone` must be an installed IANA key.
Fractional-offset zones keep truthful heatmap-unavailable behavior; no
invented counts, no analytics scope change. No asset-source change, so no
npm rebuild (avoids unrelated generated noise).

Tests: new `tests/integration/test_web_timezones.py` (12 tests:
completeness vs installed DB, order/labels, default precedence, explicit
override, invalid/traversal rejection, cross-region display with identical
UTC instants, timeline shift, fractional heatmap truthfulness, summer/
winter DST acceptance, nav preservation, settings validation, catalogue
caching) and new `tests/e2e/test_timezone_select.py` (native default/
explicit Pacific zones in both themes at 390px with Apply/reload/nav,
Asian-zone explorer + nav preservation).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/integration/test_web_timezones.py` | PASS | 12 passed |
| Full `pytest tests/unit tests/integration` (clean env) | PASS | 438 passed, 2 skipped (pre-existing loopback-bind skips) |
| Same suite with `DEFAULT_TIMEZONE=Nope/Zone AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 438 passed, 2 skipped; hermetic isolation holds |
| `ruff check .` | PASS | All checks passed |
| `ruff format --check .` | PASS | 156 files already formatted |
| `uv lock --check` | PASS | 40 packages, lockfile current, no new dependency |
| `pytest tests/e2e --collect-only` | PASS | 24 collected (22 + 2 new) |
| `pytest tests/e2e/test_timezone_select.py` execution | BLOCKED | Protected chromium launch fails inside this macOS shell sandbox (`TargetClosedError` during launch); protections kept, coordinator runs `uv run --locked pytest tests/e2e -q` outside |
| npm build / Docker / x86-64 | NOT RUN | No asset sources changed (template-only); no socket access; ARM64 only |

Acceptance impact: UI-01 (full catalogue, explicit display timezone,
stable order), UI-02/UI-05 (Apply/nav/reload preservation, server-side
proof; browser proof coordinator-owned). Independent reinspection required
before stage B. No paid/live gates claimed or passed.

## 2026-11-01 — Stage A correction (independent protected-Chromium findings)

Owner-authorized fix-first commit `773cd12` on
`feature/acceptance-polish-2026-11-01` (prior Stage A `9332bc2`
preserved, nothing reverted). Same posture as Stage A: sole writer,
exact model `muse-spark-1.3-contributor`/medium, Contributor ON,
public source + synthetic fixtures only, sandbox + approval judge ON,
no agents, no provider/product calls, no pushes/main merge/deployment,
no new dependencies, no parent/private runtime, secrets, traces or
model-key inspection.

- Real UI defect: the `filter.times_in` notice lived in
  `partials/filter_bar.html` outside `#page-content`, so htmx fragment
  swaps left it stale after Apply. Every data partial
  (`overview/crawlers/errors/requests/security_content.html`) now
  carries an out-of-band `<p id="filter-times-notice"
  hx-swap-oob="true">` update with the server-validated zone; failed
  Apply (400) carries none, so stale results keep the stale notice.
  Locale-central, no inline script, no CSP change.
- Test interaction defect: `test_asian_zone_explorer_and_nav_preservation`
  at 390px now opens the real overlay menu (`Menu` button,
  `aria-expanded`, visible `#side-nav`) and follows the actual scoped
  visible Overview link, preserving narrow layout and the Asia/Tokyo
  assertion. No forced/hidden clicks, no viewport widening.
- `app/config.py`: the `default_timezone` validator no longer calls
  `available_timezones` per `Settings` construction (which runs per
  request); one `ZoneInfo` construction proves installability. Config
  still never imports the web layer (dependency direction preserved).
- Absent `DEFAULT_TIMEZONE` (neither environment nor `.env`,
  via `model_fields_set`) now counts as unconfigured, so the
  resolver's reliable regional server `TZ` fallback is reachable in
  real routing; an explicit `DEFAULT_TIMEZONE` (including explicit
  UTC) always wins. Covered by a Settings/request-routing test, not
  only helper calls.
- Automatic `TZ` detection accepts only a defensible region key
  (`Region/City`) or `UTC`: `CET`/`EST`/`Etc/GMT+2`/path syntax fall
  back to UTC even though those aliases stay explicitly selectable
  and valid as configured values. No physical geolocation guessing.
- UTC fallback honesty: naming UTC is deterministic, but rendering
  any zone requires the system tz database — without usable zone data
  the data pages fail fast with a safe 400 (tested), never with
  silent UTC-looking output. Documents the tzdata prerequisite.

Tests: `tests/integration/test_web_timezones.py` grows 12 → 18
(no-enumeration proof, routing-level TZ fallback, explicit-alias
selectability, OOB notice on all five fragments + absent on 400,
deterministic missing-DB fallback and fail-fast 400).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused `pytest tests/integration/test_web_timezones.py` | PASS | 18 passed |
| Related web/config/nav suites + `tests/unit/test_config.py` | PASS | 97 passed |
| `pytest tests/e2e --collect-only` (incl. timezone file) | PASS | 2 timezone tests collect |
| `ruff check .` | PASS | All checks passed |
| `ruff format --check .` | PASS | All formatted |
| `pytest tests/e2e` execution | BLOCKED | Sandbox denies protected browser launch; coordinator-owned |
| Docker/x86-64 | NOT RUN | Coordinator-owned |

Acceptance impact: UI-01/UI-02/UI-05 corrections only; Stage A work
otherwise intact. Independent reinspection required before/after
stage B. No paid/live gates claimed or passed.

## 2026-11-01 — Stage B AI readiness corrections (offline-only)

Owner-authorized bounded slice on `773cd12`, branch
`feature/acceptance-polish-2026-11-01`. Same posture: sole writer,
exact model `muse-spark-1.3-contributor`/medium, Contributor ON,
public source + synthetic fixtures only, native mocked Meta transport
with synthetic dummy keys, `socket.connect` blocked in tests, all
databases temporary synthetic test stores unrelated to the exhausted
ledger. No agents, no network/product/provider calls, no pushes/main
merge/deployment, no new dependencies, no cap/allowance changes, no
rerun of the real smoke runner. The independent runner's BEFORE
numbers were reproduced first with an owned stubbed script
(`displayed 47366 vs settled 23683`; `73451 vs 48567`;
`output_limit_reached` before dispatch 2 with 1 transport call on
scope example-combined WIN_C 2026-10-28T09Z..10Z); after the fix the
same script reports exact agreement and 2 dispatches for the 3-tool
case. Fake measured counts derive from stub wire length, never from
actual product spend.

1. Context minimization (AI-01/PRIV-01): `history_line` is no longer a
   `repr` of minimized evidence. New `egress.project_evidence_summary`
   builds one deterministic bounded projection per tool result —
   exact `[evidence {tool_call_id}]` ID, tool name, actual observation
   time, full executed scope (site/source/window + selected matchers),
   coverage and a compact per-tool result (counts, rule refs, bounded
   row/text samples with explicit `[+N more]`/`[+N more chars]`
   markers) — from already-validated values, then re-validates the
   complete final string. Overflow raises `payload_too_large` (mapped
   to `output_limit_reached`) before further dispatch; hostile shapes
   still fail first in `serialize_evidence` and are never thinned
   into safety. The same projection travels in fake history lines and
   native stateless `function_call_output` items (typed metadata:
   `tool_call_id`, `tool`, `observation_time`, `summary`).
   `HISTORY_MAX_CHARS=4000` is unchanged, full local envelopes and
   reproducible server evidence links are untouched, all per-step
   gates/reservations/budget days/cancellation/timeout/tool bounds
   and provider-failure handling are intact. The old history-bound
   regression still trips on its workload, proving the unchanged
   limit.
2. Estimated cost (COST-01/02): the real final branch displayed
   `spent + step_actual` although `spent` already included the step —
   now displays exactly `spent_micro_usd`. The fake path accumulates
   each settled incremental estimate and displays that exact sum
   instead of a re-rounded total. Returned usage now equals the
   settled per-step ledger in one-dispatch, tool+final and
   multi-step cases, with cached/reasoning subsets and synthetic
   budget/smoke ledgers; settlement math and caps are untouched and
   no historical usage was altered. The t8 combined assertion stays a
   `>=` bound (per-step ceiling) while new tests assert exact ledger
   equality with rounding coverage.
3. Citations and observation wording (AI-02/AI-03): the system prompt
   now requires exact `[evidence {tool_call_id}]` citations, separates
   actual observation time from the requested window, mandates
   claimed-bot / investigation-candidate / unavailable-timing wording
   and requires truncated/partial disclosure (contract only — no
   claim that wording guarantees model output). Also fixed the real
   user message dropping `method`/`status`/`path_prefix`/
   `referer_host` and the duplicated `status_class` line in
   `_compose_user_text`. Deterministic prompt/wire/UI contract tests
   assert the wording, metadata and scope without demanding exact
   free prose from any model.

Tests: new `tests/integration/test_assistant_stage_b.py` (18 tests):
scripted-native A/B/C three-case test with actual analytics tools
and T8 WIN_C goldens (exact counts/scopes/local envelopes, wire
within unchanged limits, paired call IDs); 9-in-one and total tool
overflow, interruption/gate-switch/budget exhaustion, poisoned
question (zero dispatches/charges), oversized question,
projection-bound fail-closed, hostile-content serialization block,
all matchers on the real wire exactly once, native duplicate/missing
call-ID rejection, multi-step cached/reasoning exact rounding,
system-prompt contract, full-scope user-text contract, fake-history
metadata contract, wire byte-cap/validation/immutability contract,
chat UI contract (settled cost + typed evidence + evidence links).
This is offline validation ONLY — AI-02 real-call status is NOT
claimed and no production fake answering mode exists.

| Check | Result | Evidence |
| --- | --- | --- |
| BEFORE reproduction (owned stub, blocked sockets, temp DBs) | FAIL as reported | 47366 vs 23683; 73451 vs 48567; output_limit_reached with 1 call |
| AFTER reproduction (same script) | PASS | Displayed == settled in all cases; 3-tool case completes in 2 dispatches |
| Focused `pytest tests/integration/test_assistant_stage_b.py` | PASS | 18 passed |
| AI suites (`test_assistant`, `test_assistant_corrections`, `test_assistant_scope`, `test_t8_preparation`, `test_meta_adapter`, `test_ai_*`) | PASS | 140 passed (incl. 18 new) |
| Full `pytest tests/unit tests/integration` | PASS | 462 passed, 2 skipped (pre-existing loopback-bind skips) |
| Same full suite via `uv run --locked` (focused files) | PASS | 36 passed (18 timezone + 18 stage B) |
| `ruff check .` | PASS | All checks passed |
| `ruff format --check .` | PASS | 157 files already formatted |
| `uv lock --check` | PASS | 40 packages, lockfile current, no new dependency |
| `pytest tests/e2e` execution | BLOCKED | Sandbox denies protected browser launch; coordinator-owned |
| Docker/candidate/smoke/x86-64 | NOT RUN | Coordinator-owned; no socket access |

Acceptance impact: AI-01/AI-03 (bounded typed tool investigation with
minimized context and explicit evidence), PRIV-01/02 (egress boundary
unchanged and re-proven over the new wire shape), COST-01/02 (exact
settled display, caps/ledgers intact), API-04 (chat contract without
raw-log/proxy regressions — full suite green). Prior incomplete real
AI demo and no-new-paid-call status retained. Independent
reinspection required; no merge to `main`, no production deployment.

## 2026-11-01 — Independent correction: timezone residuals + AI projection truthfulness

Six confirmed in-scope defects on bc1e057 fixed; cost-display fixes
(onecall24524/50327/52889) preserved; 4000/8000/65536 caps and all
budget/egress gates unchanged.

| Check | Result | Evidence |
| --- | --- | --- |
| BEFORE reproduction (stubbed native, blocked sockets, temp DBs) | FAIL as reported | Full Overview DOM has 2× `filter-times-notice`; TZ=Asia/Tokyo unset-config orders UTC first while selecting Tokyo; wire says `sec-repeated-client-errorsx0`, `buckets=10 ...requests=0` over a 72-bin/30-event window |
| AFTER: full pages 1 notice, partials 1 OOB notice, Apply-fail none | PASS | New `test_web_oob_notice.py`: 6 passed |
| AFTER: effective default orders options + labels Settings; explicit URL wins | PASS | Same file; existing `test_partial_swap_carries_updated_timezone_notice` still green |
| AFTER: findings carry named counts + v1; timeseries 72 bins/30 requests on wire AND fake history | PASS | New `test_assistant_projection.py`: 8 passed (incl. native↔fake normalized-equality, exact-scope parse-back incl. `;|`
`[evidence fake]`, overflow fail-closed, poison/legacy withheld + failed-import warning) |
| Full `pytest tests/unit tests/integration` | PASS | 476 passed, 2 skipped (pre-existing loopback-bind skips) |
| `ruff check app tests` + `ruff format --check app tests` | PASS | All checks passed; 114 files formatted |
| `pytest tests/e2e/test_timezone_select.py` | BLOCKED | Sandbox cannot launch headless shell (TargetClosedError at browser launch); environmental, not a product regression |
| Real AI-02/x86/Docker/smoke | NOT RUN | No production transport, key, account or paid call; pending gates unchanged |

Acceptance impact: timezone display consistency (filter bar, Settings,
OOB updates), AI-01/AI-03 (truthful bounded evidence on both model
paths), PRIV-01/02 (egress re-proven; hostile/legacy diagnostics
withheld; no raw logs, IPs, secrets or clients cross), COST-01/02
(ledger/display untouched, suite green). Historical failures and
pending gates preserved. No merge, no deploy, no new dependencies.

## 2026-11-01 — Tiny readiness correction: source-change quality + decoded scope validation

Two confirmed residuals on 9e7d81a fixed; all working fixes preserved
(timezone default/notice, named security counts, 72-bucket/30-request
series, exact per-step cached/reasoning display). Caps unchanged
(1600 projection / 4000 history / 8000 outgoing / 65536 wire); fail
closed retained; no raw `error_summary` text, paths or credentials
cross; no cap increases or history/allowance resets.

| Check | Result | Evidence |
| --- | --- | --- |
| BEFORE reproduction (owned probes, blocked sockets, temp DBs) | FAIL as reported | `check_outgoing(raw)` BLOCKED `raw_log_line` but `project_evidence_summary(... path_prefix=raw ...)` ALLOWED escaped JSON; `_projection_quality` for completed `source_changed_during_import; source_content_mismatch` carried only `imports_by_status completed:1` with no warning |
| AFTER: escaped Combined-like scope blocked decoded | PASS | `project_evidence_summary` BLOCKED `raw_log_line` for `/x - - [28/Oct/2026...]` host `/x` (no IP), Unicode variant and `api_key` poisoned suffix; `/ok` scope stays exact |
| AFTER: completed source-change/mismatch + withheld on every tool | PASS | `_projection_quality` emits fixed `source changed during import`, `source content mismatch`, `diagnostic withheld: legacy format` notes for `get_summary/timeseries/top_paths/security_findings/error_groups`; native wire and fake history both carry them with underscore codes absent and full local envelopes retained |
| Focused regression `test_assistant_projection + test_ai_egress + test_assistant_stage_b + test_assistant/scope/corrections + test_t8_preparation + test_web_timezones` | PASS | 147 passed |
| AI unit `test_ai_budget/gate/tools` | PASS | 22 passed |
| New projection tests | PASS | `test_assistant_projection.py`: 10 passed (8 prior + 2 new) |
| `ruff check app tests` + `ruff format --check app tests` | PASS | All checks passed; 114 files formatted |
| `pytest tests/e2e` execution | BLOCKED | Sandbox cannot launch headless shell; coordinator-owned |
| Docker/x86-64 / real AI-02 smoke | NOT RUN | No production transport, key, account or paid call; coordinator-owned |

Acceptance impact: AI-01/AI-03 (quality signals complete on every
tool), PRIV-01/02 (decoded scope/metadata validated before
compact/escaping with final string check retained; masking and exact
scope unchanged). No merge to `main`, no deployment, no new
dependencies.

## 2026-11-01 — Acceptance readiness closeout (independent final evidence, reported append-only)

Independent coordinator final evidence for clean application source
`bb272a9` on the reviewed public/synthetic branch
`feature/acceptance-polish-2026-11-01`, exactly as supplied in
`artifacts/task-inputs/acceptance-final-evidence.md`. This section
only transcribes the runner's reported outcome; the documentation
writer did not re-execute coordinator checks, read parent/private
runtime, credentials, traces, keys or history, make provider/product
calls, or change application, test, fixture or configuration files.
All historical PASS/FAIL/BLOCKED/NOT RUN records above are preserved
unchanged.

- Application freeze: `bb272a94b9001949510126f7a700da6fbc65230a` on
  `feature/acceptance-polish-2026-11-01`. All Muse writers finished
  before verification. The canonical checkout is integrated on a
  separate `local/acceptance-readiness-2026-11-01` branch at
  equivalent `ad6d74fae4cb0695e719db80e79bc2a95f`, tree clean, entire
  tracked tree identical. Prior local analytics branch `d11e8ee` and
  T10 branch `236387c` preserved; `main`/`origin/main` (`836769b`)
  unchanged; no new push/merge/production/public deployment.
- Maintained unit+integration: 480 PASS, 0 skipped, 4 warnings in
  30.32s clean; 480 PASS, 0 skipped, 4 warnings in 30.18s under
  `AI_ENABLED=true LLM_WARN_AT_USD=999`. Protected Chromium E2E:
  24 PASS, 0 skipped, 1 warning in 22.77s. Ruff check PASS, format
  159 files PASS, `uv lock` 40 packages PASS, `git diff --check`
  PASS. No dependencies changed.
- Independent native-protocol mock probe (`socket.connect`
  hard-BLOCKED, dummy test keys, temporary synthetic DBs only):
  121 checks PASS across A12/B10/C8 plus a fourth full 120-row rich
  window. All complete two-native-format mocked dispatches; exact
  per-step integer cost including cached/reasoning matches displayed
  cost, budget ledger and smoke ledger; IDs, scope/time/coverage
  transmitted; paired calls/outputs and the 65536 wire cap hold;
  exhausted synthetic allowance blocks a further dispatch with zero
  extra calls. This is OFFLINE evidence, never a real AI-02 pass.
- Independent semantic probe: actual model-visible named counts C
  `errors` 5 / `distinct_paths` 5 and sensitive-path `requests` 2 /
  `distinct_paths` 2 with rule version 1. Time series now 72 hour
  bins / 30 requests / 10 errors, full actual first+last stamps,
  explicit 67 not-shown sample bins. Exact filters retained; actual
  observation timestamp distinct from window. Completed-but-
  source-changed import warning visible for the security tool;
  legacy raw diagnostics withheld. Direct and maintained regressions
  prove decoded scope/metadata scanned before JSON encoding: raw
  Combined-like metadata cannot bypass via escapes. No
  parser/auth/retention changes; shared analytics/contracts
  preserved; read-only tool allowlist and Standard fail-closed
  egress, step/history/budget/cancellation limits unchanged.
  Independent diff/security reinspection of these changed paths
  completed; no unresolved blocking finding in this slice, no
  all-project/release certification.
- Timezone catalog: cached installed IANA keys, readable labels,
  effective server default first then UTC, remaining region/city
  sorted without duplicate values. Explicit valid URL wins;
  otherwise `DEFAULT_TIMEZONE` config, reliable regional TZ when
  unconfigured, else UTC. No Internet geolocation or guessed
  physical host location. Default/order/Settings match; one
  full-page notice and correct htmx OOB updates; failed Apply
  preserves prior state. All region aliases explicitly available;
  automatic abbreviations/fixed offsets are never guessed. Real
  timestamps honor Asian/Pacific/US/Australian zones and fractional
  offsets. UTC storage/input window/public API contracts unchanged.
  Existing fractional-offset heatmap unsupported-state remains
  explicitly unavailable. Missing tzdata fails safely.
- Fully redacted Gitleaks: tracked-export directory plus all 17
  public commits — scanner exit 1 ONLY for the known
  `technical-spec.md:787` generic-api-key cost-heading false
  positive, no new finding, no allowlist. Public history
  metadata/blob audit: zero development-tool-provenance matches;
  functional crawler identifiers intact. No private canonical
  history published or copied to Contributor context.
- Fresh tracked-export Docker build (includes npm asset
  build/check-external), isolated candidate Compose 8 PASS / 0
  FAIL, 120 rows, original 30 + new 90, replay 0/30 + 0/90,
  restart persistence, owned teardown. Internal-network/offline
  maintained smoke 24 PASS / 0 FAIL with AI off, empty model key,
  no Internet: API/client/restart/backup/isolated restore/
  retention/source read-only/owned cleanup. Actual Linux ARM64
  containers on OrbStack; native Linux x86-64 and standalone Linux
  host install NOT RUN. No new performance claims.
- Actual built-image browser matrix: 32 PASS on isolated candidate
  18091, SAME 32 PASS on persistent 8080 after upgrade (8 routes x
  light/dark x 1440/390), no console/off-origin/failed-response
  errors, Chart.js/data agreement, claimed 45 and GPT 16
  filters/nav. Additional actual-image timezone acceptance 7 PASS
  on candidate AND 7 PASS on persistent demo: exact installed
  catalogue 599 keys, no duplicates, proper priority/sort/readable
  labels; Apply/nav/reload and exact latest-row local times for
  Kathmandu/Auckland/New York/Adelaide; both 390px themes no
  overflow/errors/external requests. Candidate default UTC; actual
  demo configured default Europe/Berlin.
- Canonical demo updated with the EXACT tested image
  `logcarve-candidate:bb272a9…` (locally tagged `logcarve-demo:t10`);
  no host-context rebuild substituted. Non-root 10001, loopback
  `127.0.0.1:8080`, AI off, empty model key, read-only synthetic
  mounts. Consistent online backup 0600 plus old-image rollback
  retained before update. EVERY database table/row and both demo
  credential files unchanged across image activation; 120 requests,
  schema 4, integrity ok. Live API: existing token valid, all 120 /
  old-exclusive 26..29 Oct 30 / claimed 45 / GPT 16; actual stdlib
  client all 3 replies PASS; missing-token 401 body/header
  `request_id` parity. Health script: `healthz` 200 AI-off, unauth
  `readyz` 401, private admin `readyz` 200 schema 4. All temporary
  owned candidate containers/networks/volumes/credentials removed;
  actual 8080 left RUNNING.
- No new product/provider calls, no actual allowance reset or usage
  mutation. Muse coding usage is separate, exact coding cost not
  claimed. Historical real Meta smoke: 2 successful of 3
  investigations, third failed closed; real AI-02 remains
  INCOMPLETE, not rerun after the fix. Extra real work requires a
  new explicit bounded authorization respecting existing state; do
  not reset/recreate/restore ledgers. Product demo stays AI-off.
  Owner manually accepts TODAY; acceptance/video/publication are
  NOT yet executed.
- Fixed demo URL:
  `http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined`

Acceptance impact: timezone display catalogue (A), three offline AI
corrections (B) and technical local gates (C) are complete at this
anchor; owner manual acceptance is pending. Model-visible scope
metadata (named counts, timeseries bins, sample semantics,
import-quality notes) is independently reverified. Historical real
AI 2-of-3 INCOMPLETE, no-new-paid-authorization, actual-demo-AI-off
and x86-NOT-RUN are preserved. Coding Contributor usage stays
separate from product Standard/data-egress/caps.

## 2026-11-01 — Stage A owner-UX review (plan + labels/offsets/dropdowns/Crawlers/Help/starter/quick views)

Bounded implementation on `feature/owner-ux-review-2026-11-01`, sole writer,
exact model `muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, no agents/calls/push/main merge/production/deploy. Synthetic
fixtures only; no schema/data migration, fixtures/digests/seeds untouched.
Plan: `docs/owner-ux-review-plan.md` (date/reason, A1–A11, Stage B deferred).

Change: presentation-only label/data separation (`display_bot_title`,
`category/provider/purpose/status/human_bytes` display helpers; rule
YAML, API fields/IDs/versions/provenance, stored data untouched);
timezone option labels carry the signed UTC offset at the APPLIED window
start (`format_offset_suffix`, bounded cached ZoneInfo, ETC/GMT-reverse,
fractional, DST both sides, historical sub-minute seconds, malformed →
"UTC offset unavailable"); offset notice updates only on successful
Apply/OOB with DST caveat; method/status are native dropdowns (All +
`http.HTTPStatus` standards + scoped observed/current-selected values,
two bounded parameterized queries, permissive parsing unchanged);
Crawlers groups stacked full-width with `.bot-name{white-space:nowrap}`
(local rebuild, no page-overflow hiding); session-gated `/help` + sidebar
with safe placeholder curl/stdlib examples and Google verification link
(documentation only, no network); Ask AI starter 9 (manual-review
firewall draft, populate-only, never applies/invents IPs); five Overview
quick views preserving site/source/window with explicit matcher
replacement + paging reset; status phrases + readable bytes as table
polish; `traffic.claimed_bot` reads "Bots" with browser-like/identity
legends. Stage B (8-column Requests overview, conflicting-bot signal)
explicitly NOT implemented here.

Actual results (project .venv, Python 3.12.16, same session, clean tree
before commit): new `tests/unit/test_owner_ux_labels.py` (11 tests:
prefix strip, category map, Unspecified, phrases incl. unregistered,
human bytes, DST/fraction/Etc/GMT/sub-minute/malformed offsets,
catalog completeness, bounded cache) PASS; new
`tests/integration/test_owner_ux_stage_a.py` (12 tests: native
dropdowns, selection/observed-custom retention, no-prefix dropdown,
stacked readable groups, window-start offset incl. summer/winter,
session-gated Help with safe examples, bearer-cannot-open-UI, Help
filter state, firewall starter populate-only, quick-view scope/replace,
quick-view follow-ups) PASS; full `tests/unit tests/integration`
501 passed, 2 skipped (pre-existing skips); `ruff check .` PASS;
`ruff format --check .` PASS (164 files). Four pre-existing tests
updated for the authorized wording/count changes
(`test_web_partb`, `test_web_slice_b2`, `test_web_timezones`).
New e2e `tests/e2e/test_owner_ux_stage_a.py` (filters/offset,
Crawlers nowrap, Help, 1440/1024/768/390 both themes): BLOCKED in this
sandbox — chromium launch denied by the enclosing sandbox
(MachPortRendezvous permission, kill EPERM); no retry, no weakening;
coordinator runs `uv run --locked pytest tests/e2e -q` outside it.
Docker/8080 NOT RUN here. No product/provider calls, no purchases.

## 2026-11-01 — Stage B owner-UX review (Requests overview, conflicting-bot signal, A-findings fixes)

Bounded implementation on `feature/owner-ux-review-2026-11-01`, sole
writer, exact model `muse-spark-1.3-contributor`/medium/Contributor ON;
sandbox + approval ON, no agents/calls/push/main merge/production/
deployment. Synthetic fixtures only; no schema migration, no
120-row/digest/seed changes; original demo fixtures byte-identical.

Change: B1 8-column Requests overview + expandable per-row details +
14 allowlisted server sorts (legacy `newest`/`oldest` stable,
timestamp/id tie-breaks, NULL-bytes-last, filters/paging before/after
sorting); B2 original `sec-conflicting-bot-identity` v1 (security
ruleset v1→v2, bot catalog 77 unchanged, first-match order unchanged)
with explicit 9-token URL-stripped token-boundary detection shared
across a SQLite UDF, exact all-row aggregation and the deterministic
`security_findings` path (API + assistant tools see identical
counts/rule-version/limitations); B3 "Largest responses" → Requests
`bytes_desc` plus status-phrase/byte polish. Stage A coordinator
findings fixed: ZoneInfo cache 1024, OOB option-label refresh,
largest-link retarget, Edge/Opera-before-Chrome, bots+automation note,
unique e2e basename, semantic identity-legend assertion. No
DNS/HTTP/GeoIP/unmasking, bot removal, model tools, shell/files
actions, or allowance/dependency changes.

Actual results (project .venv, Python 3.12.16, same session, clean
tree before commit): new `tests/unit/test_conflict_detection.py`
(10 tests) PASS; new
`tests/integration/test_owner_ux_stage_b.py` (17 tests: every sort
asc/desc with hand-derived orders, paging/filter/API-vs-service
agreement, hostile-sort 400, cross-site/source bounds, legacy sort
stability, privacy, conflict positives/negatives, exact counts,
5100-distinct-agent exactness, bounded samples, AI projection caps,
browser-family regression, web columns/details/OOB/quick-link/API
agreement) PASS; updated maintained tests
(`test_owner_ux_stage_a` +OOB test, `test_web_slice_b2` 8-column
headers, `test_rules` ruleset v2 + new rule, `test_traffic_api`
`ua_truncated`/`conflict` fields) PASS; renamed
`tests/e2e/test_owner_ux_browser.py` (unique basename, semantic
legend, new sort/details keyboard/back/reload coverage). Full
`tests/unit tests/integration`: 529 passed, 2 skipped (pre-existing
skips). `ruff check .` PASS; `ruff format --check .` PASS (167
files). Authored assets rebuilt locally (`npm run build:js`,
`npm run build:css`; generated `app/web/static/app.css` diff
inspected; `static/js` outputs stay gitignored per project
convention) and `node scripts/check_no_external.mjs` PASS (no remote
refs). New e2e file: NOT RUN in this sandbox (chromium launch
denied as in Stage A; no retry, no weakening); coordinator runs
`uv run --locked pytest tests/e2e -q` outside it. Docker/8080 NOT
RUN here. No product/provider calls, no purchases.

Acceptance impact: owner-UX Stage B complete at this anchor; owner
manual acceptance still pending. Historical real AI 2-of-3
INCOMPLETE, no-new-paid-authorization, actual-demo-AI-off and
x86-NOT-RUN are preserved. Coding Contributor usage stays separate
from product Standard/data-egress/caps.

## 2026-11-01 — Stage B owner-UX review correction (conflict boundary, captions, Help prose)

Bounded sole-writer correction on `feature/owner-ux-review-2026-11-01`
after Stage B commit `3bcb915`, exact model
`muse-spark-1.3-contributor`/medium/Contributor ON; sandbox + approval
ON, no agents/push/main/deploy. Synthetic fixtures only; no schema
migration, no 120-row/digest/seed changes, no dependency/allowance
changes, no asset rebuild (no authored JS/CSS/template-class change).

Corrections: conflict detector token boundary now treats `_` and `-`
as word characters, so `some_Googlebot_clone/1 bingbot/2` and
`my-Googlebot-tool/1 bingbot/2` each claim only Microsoft (no
conflict); documented Google product variants `Googlebot-Image`,
`Googlebot-News`, `Googlebot-Video` added explicitly (12-token known
set, same-provider pairs stay negative; versions, semicolon pairs and
Mozilla-only strings preserved). Crawler group title/chart renamed to
"Bots and automation ..." with a recognized-bots-plus-automation
membership note (counts unchanged). Help `api_body` literal
`Bearer [REDACTED]` replaced with "scoped API tokens" (code examples keep
`<YOUR_TOKEN>` placeholders); explorer Help now states sorts restart
at the first page while paging advances keeping sort/scope; filter
Help and the quick-view note state exact traffic/status replacement
sets (traffic views replace traffic+bot/category/provider/purpose,
status views replace status+status class, Largest presets the sort).
Conflict Help documents the limited known set and the affix exclusion.

Tests: extended `test_conflict_detection` (variant positives,
single and combined-with-second-provider affix negatives,
same-provider variant pairs); new `test_owner_ux_labels` caption /
Bearer-literal / sort-paging / quick-view / known-set assertions;
`test_web_slice_b2` and e2e crawler heading updated to the new title;
`test_owner_ux_stage_a` quick views assert bot/category/provider/
purpose are dropped together. No existing privacy/filter/time/count
coverage removed.

Actual results (project `.venv`, same session): review probe
`some_Googlebot_clone/1 bingbot/2` False, `my-Googlebot-tool/1
bingbot/2` False, `Googlebot/2.1 + bingbot/2.0` True,
`Googlebot-Image/1.0 + bingbot/2.0` True, semicolon pair True,
same-provider pair False, docs-URL single claim False (ALL-OK).
Focused `pytest tests/unit/test_conflict_detection.py
tests/unit/test_owner_ux_labels.py
tests/integration/test_owner_ux_stage_a.py
tests/integration/test_web_slice_b2.py
tests/integration/test_owner_ux_stage_b.py`: 66 passed.
`ruff check .` PASS; `ruff format --check .` PASS (167 files).
`uv run --locked` unavailable in-session (uv cache permission denied);
no manifest change, so `uv.lock` untouched. Browser E2E, full clean
suites, fresh-image and runtime checks stay coordinator-owned (NOT RUN
here). No product/provider calls.

## 2026-11-01 test-only browser corrections (2 failures at a087c3e, no app change)

Protected Chromium run reported 29 tests: 27 PASS, 2 FAIL, 36.98s.
Both failures are test-side selector semantics; application code unchanged.

1. `tests/e2e/test_owner_ux_browser.py::test_requests_sort_headers_and_details`
   (line 261): `page.wait_for_selector(f"tr#{panel_id}[hidden]")` uses the
   default `visible` state, so a correctly hidden row never satisfies the
   wait (24 polls observed). Per Context7 primary `/microsoft/playwright-python`,
   `wait_for` defaults to visible; `state="attached"` waits for DOM presence.
   Fix: wait `[hidden]` with `state="attached"`, then assert the same panel
   occurs exactly once, `is_hidden()`, and `aria-expanded == "false"` after
   the Enter-key toggle. No app change.
2. `tests/e2e/test_slice_b.py::test_explorer_columns_sanitized_and_timezone_aware`
   (line 481): `get_by_role("link", name=re.compile(r"Time \(Europe/Berlin\)"))`
   raises `InvalidSelectorError` (regex serialisation leaves the `/`
   unescaped). Fix: deterministic CSS-scoped header link
   `page.locator("thead th", has_text="Time (Europe/Berlin)").locator("a")`
   for both asc/desc clicks, avoiding regex-with-slash. Asc/desc row ordering,
   UTC titles, timezone display and privacy assertions preserved; local
   `import re` removed (no other use). No app change.

Checks here: `pytest --collect-only` 11 tests collected; `ruff check` PASS;
`ruff format --check` PASS (2 files). Full protected browser run stays
coordinator-owned: browser PASS is NOT claimed here.

## 2026-11-01 test-only correction (second `[hidden]` wait, no app change)

Protected Chromium at 71a7808 reported 29 tests: 28 PASS, 1 FAIL, 37.74s.
Last failure `tests/e2e/test_slice_b.py::test_explorer_columns_sanitized_and_timezone_aware`
(line 506) is the second occurrence of the same wait bug fixed at 71a7808 in
`test_owner_ux_browser.py`: `page.wait_for_selector(f"tr#{panel_id}[hidden]")`
waits default VISIBLE, so the correctly hidden row never satisfies it
(24 polls). Fix: same pattern as the prior fix — wait `[hidden]` with
`state="attached"`, then assert the same panel occurs exactly once,
`is_hidden()`, and `aria-expanded == "false"` after the Enter-key toggle.
Searched all `tests/e2e` for remaining selector+`[hidden]` waits without
explicit state: none left (`:not([hidden])` waits correctly use default
visible). Keyboard-close, aria, full-HTML, privacy, time and row-order
checks preserved. No app/config/fixture change.

Checks here: `pytest --collect-only` 7 tests collected
(tests/e2e/test_slice_b.py); `ruff check` PASS; `ruff format --check` PASS.
Full protected browser run stays coordinator-owned: browser PASS is NOT
claimed here.

## 2026-11-01 — Owner-UX closeout (independent final evidence, reported append-only)

Independent coordinator final evidence for the owner-UX slice on public
`feature/owner-ux-review-2026-11-01` at HEAD `f0182fb`. Application anchor
is `ffaf737`; commits after it are tests/docs ONLY, so the tested runtime
image was built from `a087c3e1497b1ca3e9144a8fb0e072d8a8bed6b0` — no fresh
build is claimed for the later docs/test-only commits, and those commits
need no broad test repeat. No writer edits to app/tests after this point.
No push, main merge, production deployment, product/provider calls, purchases, or
allowance reset/restore. Sole-writer Muse coding with exact
`muse-spark-1.3-contributor`/medium, protections ON, no agents; public
source + synthetic fixtures only. Historical PASS/FAIL/BLOCKED/NOT RUN
records above are preserved unchanged.

| Check | Result | Evidence |
| --- | --- | --- |
| Locked `pytest tests/unit tests/integration` clean + `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 536 passed, 0 skipped each (32.15s / 31.25s); Python 3.12.16 macOS arm64; no dep/lock/schema change |
| Protected Chromium `pytest tests/e2e` | PASS | 29 passed, 0 skipped (27.08s); window DST label Apply + failed-Apply state, 8 typed columns, UA escaping, Time UTC title, asc/desc, keyboard details, 9 starters with disabled send, scope/nav, charts/tables/API/themes/mobile |
| Earlier E2E 19/9, 27/2, 28/1 | FAIL (historical, preserved) | Stale/unstable maintained-test expectations corrected by test-only commits; app detail behavior was working, `wait [hidden]` default-visible test bug closed |
| Network-blocked 10-row full API probe + existing 28-row regression | PASS | 78 + 53 checks: 12 sort directions + legacy newest/oldest, paging, filters, unknown-sort 400, cross-source 403, NULL-bytes-last, 4 identity conflicts incl. >200-char UA sample, truncation flag, no IP/query leak, source hash/integrity, affixed-product negative |
| Native-wire fake-provider regression | PASS | 121 checks across A/B/C/full-120 windows: evidence IDs, named counts, rule versions, scope/coverage/quality, cached+reasoning microUSD ledger, caps, exhausted SYNTHETIC allowance |
| Real Meta smoke | INCOMPLETE (historical, preserved) | 2 of 3 completed, third stopped at its context bound; no fresh paid authorization; real allowance never reset/restored/recreated; no actual Meta calls here |
| Changed-path review (analytics/API/web/classifier) | PASS (slice only) | Fixed SQL sort allowlist + bound values, stable ties, scope-before-order, paging bound, 200-char UA + truncation flag, full-stored-UA identity decision, bounded cached 12-product/9-provider detector, no DNS/GeoIP/exclusion, exact all-row counts beyond 5100 agents, escaped output, session-gated Help, unchanged scoped API/CSRF/egress/tools/ledger; no unresolved high/medium defect in this slice — NOT whole-project QA-01/release approval |
| Ruff / lock / diff | PASS | `ruff check` + format on 167 files, `uv lock` 40 packages, `git diff --check` |
| Docker tracked-export build | PASS | npm asset build + external-refs check, locked deps, local resources only |
| Fresh isolated Compose candidate | PASS | 8/0 (120 seed, replay, digests, restart); Linux ARM64 image; owned resources removed |
| Internal-network offline Compose | PASS | 24/0 (no external network/model key/chat; API/client, backup/isolated restore, retention, cleanup); owned resources removed |
| Built candidate + upgraded live 8080 | PASS | 36 route/theme/width cases each (9 routes incl. Help, 1440+390, light+dark); 8 timezone checks each (all 599 zones, default/order/labels, Kathmandu/Auckland/New York/Adelaide exact times, summer/winter OOB refresh, invalid Apply, narrow themes); 12 UI interaction checks each (header clicks vs external API, keyboard details, details after htmx Apply, both themes); no console errors/external requests/overflow/failed responses |
| 100k synthetic profile (macOS 27.0.1 arm64, M5 Pro 18 cores/48GiB, Python 3.12.16) | Observed | 98969 accepted / 1031 by-design rejected, 2.0801s import, 45916160 DB bytes, peak RSS 169.53 MiB; byte-sorted Requests 0.1841/0.8048s, Security 0.2931/0.9566s, Overview 1.4416/3.1017s, Crawlers 1.1949/1.4437s; single observations, not percentiles/guarantees |
| Redacted Gitleaks history + tracked export | Known finding (exit 1) | Only the known `technical-spec.md:787` cost-heading false positive (`generic-api-key`, exit 1 retained); no allowlist, no new finding; no work-origin naming trace; functional User-Agent catalog data retained unchanged |
| Live update 127.0.0.1:8080 | PASS | EXACT tested image `logcarve-candidate:a087c3e…`, UID 10001, loopback only, RO source mounts, AI off, empty key, default Europe/Berlin; online 0600 backup + rollback image taken BEFORE activation; all-table/row hashes identical across activation; credential hashes unchanged; 120 rows, schema 4, admin/token/sessions/usage retained; later logins create only their own sessions; pins `d765393f…ebeb65` / `b9479a8e…52ca45f` unchanged |
| Linux x86-64 / standalone host install | NOT RUN | ARM64 only; no x86/amd64 claim |
| Persistent demo network posture | Noted | Ordinary bridge loopback demo is NOT air-gapped; offline proof is the separate internal-network run |

Acceptance impact: owner-UX Stage A+B (ANA-01/03/04/05, UI-01/02/03/05,
API-01/05, AI-01/03) complete for this changed slice at the above
evidence; owner manual acceptance pending; no full release or QA-01
certification. Changed requirements recorded 2026-11-01: plain named-bot
labels with one identity legend (ANA-03/UI-01); 599 signed period-start
offset labels with DST caveat (UI-01/02); human category labels,
full-width bot groups, "Bots and automation" 63 vs 45-member wording
(ANA-03/UI-01); method/status native dropdowns (ANA-05/API-05/UI-02/05);
8-column Requests explorer with 14 sorts incl. legacy + sanitized
details (ANA-05/API-05/UI-02/05); conflicting-bot candidate as
investigation lead only, absence proves nothing (ANA-03/AI-03);
authenticated Help + input-only firewall starter (UI-01/02/AI-01);
quick views incl. Largest responses (UI-02/05/ANA-05). Honest limits
kept: no fifth "user generated" class (Browser-like is an explanatory
same-bucket quick view, not a metric); identity conflicts are neither
verified fake/real nor auto-exclusion; no IPs/countries/humans/
sessions/conversions/indexing/ranking/training claims. Product demo
stays AI-off; AI-02 stays INCOMPLETE; no new paid calls authorized.

## 2026-11-01 — Parity T1a: gzip + preset ingestion (PAR-01, implementer run)

Implementer: Muse Spark 1.3 Contributor, medium, protections ON, sole
writer, no agents. Public/synthetic only; no outside files, screenshots,
real keys, Docker, actual Meta, push/main or deploy. No upstream LogWerk
code copied: parsers, gzip, autodetect, custom validation and host filter
are original implementations (77-rule bot catalog and 120-row fixture
bytes/goldens untouched; `d7ab80c` provenance stays in
`THIRD_PARTY_NOTICES.md`).

Scope kept to ownership: `app/ingestion/*` (presets, gzip, autodetect,
custom, host plumbing), minimal `app/db/importer.py` + `app/db/cli.py`
plumbing, `app/config.py` import limits, new synthetic fixtures/tests.
No web/API changes, no private-IP persistence, no schema migration
(T1b follows). `CombinedRecord.extra` carries normalized metadata so
T1b persists without reparsing; `request.http_version` retained.

Two legacy unknown-format tests (`test_combined_parser`,
`test_source_resolution`) moved their probe ID `common` → `jsonl`:
`common` is now an authorized preset, so the probes needed a
still-unknown ID. Intent (unknown IDs rejected) is preserved; no other
legacy expectation changed.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused T1a unit `tests/unit/test_parity_t1a.py` | PASS | 25 passed: 4 presets + quotes/missing/extended MIME charset/timing units/nulls + IPv6, autodetect true/ambiguous/unmatched, custom valid/invalid/evil, gzip magic/plain/concat/CRC/truncation/zipbomb/ratio/member-limit/oversize-once/all-bytes digest/no-full-read, host isolation counts |
| Focused T1a integration `tests/integration/test_parity_t1a_import.py` | PASS | 10 passed: gzip↔plain replay both directions, clean logical digest, fixed gzip failure code, host isolation end-to-end, auto (+ site-host default filter) and custom end-to-end, ambiguous fixed code, CLI file series per-file outcomes, series interruption/recovery, source bytes unchanged; manual CLI probes for gzip+auto and custom also completed |
| Full `tests/unit tests/integration` | PASS | 569 passed, 2 skipped (project `.venv`, Python 3.12); legacy plaintext T6 reader-hash/replay/transient-mutation tests unchanged and green |
| `ruff check` + `ruff format --check` | PASS | `ruff check app/ tests/` clean; format clean |
| `uv run --locked` / `uv lock` | BLOCKED | Sandbox denies `uv` cache writes (`Operation not permitted`); no manifest/dependency change exists (`pyproject.toml`/`uv.lock` untouched), project `.venv` used directly instead; coordinator re-runs locked commands |
| Browser/Docker/Meta proofs | NOT RUN | No browser automation, container build, or product calls from this run; coordinator runs protected-browser/offline/independent-review proofs |

Acceptance impact: PAR-01 partially implemented at parser/import/CLI
level (T1a). No performance/UI claims; T2 analytics, exports, masking,
GeoIP, journeys and saved views remain later slices. Stopping here for
independent re-inspection before T1b, per authorization.

## 2026-11-01 — Parity T1a correction (five findings + gzip eof boundary)

Bounded sole-writer correction on `feature/logwerk-parity-2026-11-01`,
no amend, no T1b schema. Uncommitted base preserved throughout.

| Check | Result | Evidence |
| --- | --- | --- |
| gzip eof duplicate-tail fix | PASS | Python 3.12 repro raised `interrupted:gzip_member_limit` before, yields exact 42 bytes / 2 members after; 12-combo read-size/output-cap param test green on 3.12 and 3.15 |
| `regex==2026.9.29` lock | PASS | `uv lock --offline` + `uv export --offline` + `uv sync --frozen` via `UV_CACHE_DIR=/tmp/uvcache`; installed METADATA `License-Expression: Apache-2.0 AND CNRI-Python`, `Requires-Python: >=3.10`; `uv lock --check` clean |
| Trailing extended preset + MIME | PASS | Approved trailing-host fixture incl. `text/html; charset=utf-8`; null row fixed to six trailing fields |
| Engine timeout + spec validation | PASS | `(?:a\|aa)+$` outside-group ambiguity aborts at 0.5 s engine deadline (`custom_timeout`), subprocess hard-kill failsafe; size/type caps fail with fixed codes |
| Timings finite/nonnegative | PASS | `-1`/400-digit/`nan`/`inf`/exponent reject; `s`/`ms`/`us` incl. zero; aggregate overflow rejects; outputs JSON-serializable |
| Autodetect Combined default | PASS | Twins resolve to configured flavor (candidates honest); mixed grammars fail closed; validity-based scoring; sample caps |
| Custom vhost + limits + abort | PASS | Site-hostname default incl. custom vhost; CLI exit 2 on bad limits; 16-timeout streak aborts with `interrupted:custom_timeout` |
| Focused T1a unit/integration | PASS | 52 + 14 passed (project `.venv`, Python 3.12) |
| Full `tests/unit tests/integration` | PASS | 600 passed, 2 skipped (loopback sockets unavailable in sandbox) |
| `ruff check` + `ruff format --check` | PASS | Both clean |

Acceptance impact: PAR-01 correction complete at parser/import/CLI
level; no web/API/schema changes. Stopping for independent review.

## 2026-11-01 — Parity T1b storage foundation (eight confirmed findings)

Bounded sole-writer slice on `feature/logwerk-parity-2026-11-01`, no
amend, public/synthetic checkout only. All code/tests written by the
sole writer; no product calls, Docker, push, or deployment.

| Check | Result | Evidence |
| --- | --- | --- |
| Migration atomicity (`complete_statement` + authorizer) | PASS | Comment-prefixed COMMIT rejected pre-write with neither table nor version; trigger CASE..END applies as one statement and fires; bracketed/quoted semicolons apply; mid-file failure rolls back DDL+version and retry works; held writer lock fails fast with `WriterBusy` |
| Bounded reprocess (keyset pages, hard bound 1000) | PASS | 35 rows / batch 10 over 4+ batches: `rows_matched/verified` from SQL COUNT, trace hook proves every row-materializing read carries LIMIT, unbounded helper removed, rerun idempotent with kept originals |
| Source/site binding | PASS | Wrong-site import raises `source_site_mismatch` with no new site/import/row; wrong-site reprocess with a valid separate key returns `rejected` with zero writes; owning site still enriches and reads |
| Transient capture protection | PASS | `CapturedOriginal` repr/str/JSON withhold the address; HMAC byte-exact through capture; rejections and host-skips carry no original |
| Strict key parsing, AAD, blobs | PASS | `base64(key)+'!!!'`, whitespace, bad lengths rejected; newline/unpadded URL-safe accepted; unpadded URL-safe HMAC reuse rejected; length-prefixed AAD has no delimiter collisions; TEXT blobs map to fixed `decrypt_failed` |
| Nullable legacy metadata + policy | PASS | Schema-4 upgrade keeps all 12 enrichment fields NULL; new plain imports tag `t1b.1` with NULL absent timing; custom fingerprint distinguishes timing specs |
| Exact abort accounting (plain + gzip) | PASS | Alternating timeout/valid lines: 63 lines read, 32 rejected, 31 accepted, digest unset; one genuine engine-timeout probe with subprocess failsafe retained |
| Retention FK enforcement | PASS | FKs OFF inside an active transaction raises before deleting (rows and private rows intact); normal app connection cascades and counts |
| Focused T1b unit/integration | PASS | 61 passed in `tests/unit/test_parity_t1b.py` + `tests/integration/test_parity_t1b_storage.py` (project `.venv`, Python 3.12.16) |
| Full `tests/unit tests/integration` clean | PASS | 661 passed, 2 skipped (loopback sockets unavailable in sandbox) |
| Full suites conflicting env (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 661 passed, 2 skipped |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`; no missing universal-Python metadata encountered |

Acceptance impact: PAR-02 partially implemented at parser/import/CLI
level (T1b storage foundation). The pre-existing demo-slice-C
cross-site test now asserts the mandated `source_site_mismatch`
rejection (no extra site) instead of the old silent reuse. No
web/API changes; admin IP display stays schema/helpers until T4.
Stopping for independent review; T2 and later stages await it.

## 2026-11-01 — Parity T2a shared analytics C/D + T1b preflight closeout

Authorized LogWerk parity build on `feature/logwerk-parity-2026-11-01`,
exact model `muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents. Public/synthetic checkout only:
no parent private files/keys/product calls/Docker/push/main/deployment.
All code/tests by the implementer. No web/import UI/translations in this
slice. Metric definitions and provenance: `docs/logwerk-parity-metrics.md`.

T1b preflight (frozen `9b61423` findings, rechecked and fixed first):
`CapturedOriginal` is a SecretStr-backed non-dataclass (`asdict` raises,
nested/pickle/JSON carry no plaintext); source binding re-checked inside
the write transaction with a deterministic injected-race regression
(foreign registration after precheck rolls back site/import/rows/private);
already-bound sources gain validated alias metadata via
`update_source_hosts` (alias-column only, site-guarded), persisted on
import and reprocess. Probes: partial upstream `"0.100, -"` keeps the
event with total unavailable (helper/line/import/reprocess/service
agree); ~1e308 ms pairs overflow `AVG` honestly (`None` + warning,
quantiles finite, JSON-safe, no `Inf`/`NaN`).

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t2a.py` | PASS | 21 passed: preflight (asdict/race/alias), probes (partial/overflow), hand-counted 24-row C fixture, D reports, 5100-row beyond-cap proof (project `.venv`) |
| Full `tests/unit tests/integration` | PASS | 682 passed, 2 skipped (loopback sockets unavailable in sandbox; pre-existing env category) |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta |
| 120-row fixture / HMAC / ledger / 77-rule catalog | PASS | Untouched: new tests generate tmp fixtures only; catalog count asserted 77 in-test |

Acceptance impact: PAR-03/PAR-04 implemented at the shared
service/query layer (deterministic, parameterized, bounded SQL; no
original-IP joins; legacy Combined honestly unavailable). Actual HTTP
wiring stays T3; request journeys stay T2b; no sessions/landings
invented. Stopping for independent review.

## 2026-11-01 — Parity T2a review corrections (7 findings, before T2b)

Authorized LogWerk parity correction on `feature/logwerk-parity-2026-11-01`,
exact model `muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents. Public/synthetic checkout only:
no parent private files/keys/real logs/product calls/Docker/push/main/deployment.
All code/tests by the implementer. No web import/UI/translations/API wiring in
this slice. Current branch stays unchanged; commits preserved.
Metric definitions: `docs/logwerk-parity-metrics.md` (updated; the first
T2a top-200 p95 approximation is retained there as corrected history).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused T2a corrections `tests/integration/test_parity_t2a.py` | PASS | 37 passed (16 hand-derived regressions for findings 1–7 plus updated stale assertions; project `.venv`) |
| Full `tests/unit tests/integration` clean | PASS | 698 passed, 2 skipped (loopback sockets unavailable in sandbox; pre-existing env category) |
| Full suites conflicting env (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 698 passed, 2 skipped |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta |
| 120-row fixture / HMAC / ledger / 77-rule catalog | PASS | Untouched: new tests generate tmp fixtures only; catalog count asserted 77 in-test |
| T1b preflight intact | PASS | asdict/race/alias regressions still green; no schema migration, no new indexes, no private-original joins |

Corrections (shared query/service layer unless noted):

1. `p95_desc` is now an exact global rank: one window-aggregate SQL
   statement computes every path's exact P95 (integer order-statistic
   arithmetic matching the documented interpolation) and pages
   `p95 DESC, path ASC`. The 201-path probe (200×2×1ms plus one
   1×10000ms) returns `/rarest-slowest` first with `total_paths 201`;
   pages past 200, equal-P95 ties, active filters, zero/missing/large
   finite values covered. The `SLOW_P95_CANDIDATES` bound and its meta
   keys are removed; stale test/docs claims updated.
2. `summarize().duration` and `performance_overview().latency_*` agree:
   both follow measured `request_time_ms` (valid zero included, missing
   never zero). Unavailable reason is now `no_measured_request_timing`;
   explicitly stored legacy `duration_ms` rows are acknowledged via
   `legacy_measured` + `legacy_duration_only:...` without rewriting
   core rows; Combined-only scopes stay unavailable on both read paths.
3. AI-only preserves the selected candidate set (bot/category/provider/
   purpose/traffic selectors kept on the candidate side: a
   `bot-ai-gpt` filter returns only `/gpt-only`, never `/claude-only`
   or the shared browser path) while ONLY the comparison universe
   widens. Both scopes carry distinct filters/coverage
   (`candidate.*`/`comparison.*`). Incompatible selectors (traffic
   outside `all`/`claimed_bot`, non-AI bot/category/provider/purpose)
   raise `ValueError`. Vacuous universes still flagged, never hidden.
4. Value/MIME distributions are bounded (default top-100 known groups,
   explicit `limit`/`offset`, exact whole-scope `Other` remainder with
   `shown`/`total_values`/`truncated` metadata; HIT numerator and cache
   denominator stay whole-scope exact). `Unknown` renders as a separate
   count-correct bucket ordered last at ties and past the bound; no
   guessed MIME/versions or fabricated zeros.
5. Referrer-404 totals come from an exact grouped subquery (no
   delimiter-collision encoding, separator-byte regression covered);
   every grouping key orders ties (`requests DESC, host ASC, scheme
   NULLS LAST, path NULLS LAST, target ASC`) with agreement across
   pages. `relation: all/internal/external` filters in SQL with
   matching totals; the report no longer labels all rows external.
6. CLI `--host-alias` extends the configured `--site-hostname` primary
   (shared `_resolve_explicit_hosts` for import and reprocess);
   `--host-filter` explicitly replaces it. Primary+alias+foreign
   fixtures prove the alias path counts primary+alias, skips foreign,
   binds one site, and persists aliases on already-bound sources.
7. New bounded `path_exact` selector in the shared contract/filter
   serialization: SEO/AI drilldowns reproduce exactly the reported
   path group (prefix-similar `/old` vs `/old-extra` vs `/old/child`
   covered; legacy prefix stays a widening exploration);
   contradictions reject. API/UI wiring stays T3/T4; the selector is
   documented for those consumers.

Acceptance impact: PAR-03/PAR-04 corrected at the shared layer with the
same privacy/parameterization boundaries (no original-IP joins, no
schema migration, no new indexes). Stopping for independent reinspection
before T2b journeys/security.

## 2026-11-01 — Parity T3a export-lifecycle fix + T3b assistant/client slice (implementer run)

Authorized parity T3 work on `feature/logwerk-parity-2026-11-01`,
exact model `muse-spark-1.3-contributor`/medium/Contributor ON; sandbox +
approval ON, sole writer, no subagents. Public/synthetic checkout only:
no parent private files/keys/real logs/product calls/Docker/push/main/deployment.
All code/tests by the implementer. Full T4 UI and country/follow work stay next.

Fix-first (independent T3a runtime probe): actual Starlette
`StreamingResponse.__call__` (spec 2.4) converts a `send` `OSError`
at the first `http.response.body` into `ClientDisconnect` and skips
the background task, while an unstarted row generator has no
executing `finally` — the prepared snapshot leaked. New
`ExportStreamingResponse` releases the owned `ExportStream` in an
unconditional ASGI-call `finally` (both wire protocols, cancellation,
renderer errors); generator `finally` and background stay idempotent
layers. `close_prepared` plus the stream context-manager give an
unused prepared response its deterministic close contract.

T3b (bounded assistant + client): one new allowlisted tool
`get_report` with an explicit enum (performance, slow_endpoints,
seo_redirects/client_errors/server_errors, seo_ai_only,
referrer_404s, journeys, journey_entries, comparison) over the shared
deterministic layer — no raw rows/timelines/exports; server-fixed
rankings and a server-derived previous window. Full selector set
(`path_exact`, host/HTTP/MIME/cache/TLS, timing/upstream
availability, finite ranges) propagates through ChatBody,
ValidatedScope, trusted merge, ToolArguments, evidence and links;
`false`/`0` stay real, contradictions fail safe. Tool reads hold ONE
snapshot released before any provider dispatch (proven by a
deterministic mid-read commit hook and a fake-provider
closed-connection assertion). Egress allowlist/projection cover the
new aggregates with measured-vs-missing honesty (zero measured, never
missing) and exact totals; stdlib client gains report operations and
a metadata-verified bounded streaming export download. No new locale
keys: no new visible messages (existing codes/messages reused;
client diagnostics are not locale-managed). No browser import UI, no
translations.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_export_disconnect.py` | PASS | 14 passed: actual response invocation, both formats, pre-body/first-body/mid-body send failure, cancellation, older protocol, renderer error, unused-prepared close; old pattern proven leaking (`closed: False` control) |
| New `tests/integration/test_assistant_stage_c.py` | PASS | 28 passed: selector propagation, False/0 selections, contradictions, one-snapshot commit hook, no-open-txn dispatch assertion, all 10 reports, measured-vs-null, sentinels, poison fail-closed, native-wire replay/pairing, chat-route e2e, client verify helpers |
| Full `tests/unit tests/integration` clean | PASS | 819 passed, 2 skipped (loopback sockets unavailable in sandbox; pre-existing env category) |
| Full suites conflicting env (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 819 passed, 2 skipped |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `clients` + `tests` |
| `uv lock --check --offline` | PASS | `UV_CACHE_DIR=/tmp/uvcache`: resolved 42 packages, no manifest/lock delta |
| 120-row fixture / HMAC / 77-rule catalog | PASS | Untouched: no fixture/rule/config changes in tree; new tests use tmp stores only |
| Real AI / smoke allowance | NOT RUN | No production transport, key, account or paid call; real allowance untouched (isolated temp DBs only) |

Acceptance impact: PAR-07 lifecycle hardened (deterministic cleanup
on every disconnect path, pre-header safe envelopes preserved);
AI-03/AI-04/PRIV-01-03/COST-01-02 extended to the report surface at
the fake/stubbed-wire scope with sockets denied. AI-01/02 stay NOT
RUN. Stopping for independent reinspection; no merge, push or
deployment.

## 2026-11-02 — Parity T4a private-IP web slice (PAR-02, implementer run)

Owner-authorized bounded T4a ONLY on `feature/logwerk-parity-2026-11-01`
(prior HEAD `a3ef748` preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no subagents, no new approval loop, no
parent files/keys/private history/real logs, no Docker/product/
provider calls/allowance resets/push/main/deployment. All
code/assets/tests/scripts by the implementer. Public/synthetic
current branch only; the 120 fixtures, 77 bot rules, core
HMAC/auth/usage and all previous commits preserved (no fixture,
rule or config-value changes; one existing replay-contract test
extended for the authorized new matcher keys). No browser file
import UI, no translations (central English keys only, locale
architecture untouched). Report pages/charts (T4b) and saved
views/comparison/refresh/comprehensive Help/locale audit (T4c) NOT
implemented and not claimed.

Reviewed predecessor evidence (not rerun as a gate): coordinator
independent review of frozen `a3ef748` recorded PASS for
`uv run --locked --offline pytest tests/unit tests/integration`
(929 passed including both real-loopback external-client tests)
and Gitleaks 100% redacted histories; T3b exit gate satisfied with
permission to continue to T4a. The live-loopback skips below are
the same pre-existing environmental category.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/unit/test_parity_t4a_private.py` | PASS | 14 passed: unset-full vs corrupt-pseudonym fallback, hidden-count maxhide fail-closed, compressed/expanded/mapped masking, scoped/invalid/count rejections, legacy spelling preservation, per-id duplicate binding, no/wrong/tampered/missing-key codes, referrer http/https-only, CSRF-field never-raises |
| New `tests/integration/test_parity_t4a_web.py` | PASS | 30 passed: session/CSRF/Unicode-CSRF/Bearer denial with state intact, full/masked (suffix absent incl. title/data/JSON/details)/pseudonym modes, maxhide, corrupt-settings banner + repair, no/wrong/tampered/legacy-key guidance, duplicate id binding, POST-only exact-IP search (redirect purity, legacy spelling distinction, no-echo 400s, method/session guards), all enrichment filters propagate + narrow + reject + page, API/token/session exports address-free, downloads note in every mode, sort-truth label, no-store/htmx-zero/marker/storage scans, concurrent-delete render |
| Existing replay contract `test_exact_replay_preserves_valid_values` | PASS (extended) | Expected matchers dict extended with the 10 authorized T4a enrichment keys (`None` here); all prior assertions unchanged |
| Full `tests/unit tests/integration` | PASS | 971 passed, 2 skipped (same pre-existing loopback-env category), `UV_CACHE_DIR=/tmp/uvcache uv run --locked --offline`, exit status visible, no tail-masking |
| Existing E2E in this shell sandbox | BLOCKED (environmental) | Pre-existing `test_nav_roundtrip` errors identically (`TargetClosedError`, Chromium Mach IPC `Permission denied`): the shell sandbox blocks browser launch here, not the new code; coordinator executes `uv run --locked pytest tests/e2e -q` including new `tests/e2e/test_parity_t4a.py` (settings/search/requests flows, masked-suffix DOM absence, storage/history scans, back/forward, 390px + dark) with the browser sandbox ON |
| `ruff check` + `ruff format` | PASS | Both clean over `app` + `tests` after `ruff format` on touched files (TypeError for wrong-type counts per TRY004, no unused imports) |
| `uv lock --check --offline` | PASS | No manifest/lock delta: no new dependencies (stdlib urlencoded form parsing; `python-multipart` absent so `request.form()` is never used) |
| Assets | PASS | `assets/src/js/requests.js` authored (BFCache pageshow refresh); served `app/web/static/js/requests.js` synced by the exact `build:js` copy step (served tree is gitignored build output, not committed) |
| 120-row fixture / HMAC / 77-rule catalog | PASS | Untouched: no fixture, rule or config changes in tree; new tests use tmp stores only |
| Real AI / smoke allowance | NOT RUN | No production transport, key, account or paid call |

Acceptance impact: PAR-02 private admin view implemented at the web
layer with the ADR 0003 invariants intact (API/exports/errors/tools
never carry originals; tokens never authorize them; no key
edit/display; lost keys not repairable via HMAC). PAR-03 filter
carriage completed for the web params/state/nav/paging surface;
timing/upstream availability and finite ranges validated end to end.
PAR-04/05/06/08/09/10 stay at their reviewed shared-layer state;
report pages/nav/charts (T4b), saved views/comparison/refresh/Help
coverage (T4c), follow/rotation and genuine GeoIP (T5) explicitly
not claimed. Stopping for independent review; no overall release or
owner-acceptance claim.

## 2026-11-02 — Parity T4a corrections (warm-review findings, implementer run)

Owner-authorized bounded T4a corrections BEFORE T4b1 on
`feature/logwerk-parity-2026-11-01` (frozen anchor `b1d17b4` clean,
prior HEAD preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no subagents, no new approval loop, no
private parent files/logs/keys/history, no provider/product calls, no
live activation/push/main/deploy/allowance reset. Public synthetic
fixtures only; prior work, 120-row fixtures, 77 bot rules, HMAC/auth,
usage accounting, no-browser-imports/no-translations preserved.

Frozen-tree probes reproduced every listed defect first: the exact-IP
POST returned 303 but matched 3 rows instead of 1 (a second client's
User-Agent and a third client's path both embedded the target HMAC
while only the general `search` selector existed), the selected
explorer sort was dropped from the redirect, an oversized chunked POST
streamed unbounded through `request.body()`, Ask JS serialized only
the old selector allowlist, the banner printed the raw
`private_unavailable:no_key` code, and an upstream-only row hid its
measured 12.5ms value.

`uv run --locked --offline pytest tests/unit tests/integration`
(994 passed, 2 skipped — same pre-existing live-loopback category —
exit status visible, no tail-masking) plus focused suites below.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t4a_corrections.py` | PASS | 23 passed: exact client ignores adversarial UA/path embeddings (4-row general search vs 2-row exact), unknown HMAC yields empty, malformed pseudonyms 400, exact+text intersection, IP-search redirect sets `client` (raw IP absent) preserving search/sort/limit with offset 0, service/API/export(CSV+JSON)/tool/comparison agreement, chat POST carries full trusted scope with model override losing to scope, malformed client 400 with no provider egress, 413s without echo, counted early-stop chunk bound (3 receives of 11, lying Content-Length ignored), duplicate/malformed forms 400, invalid-Unicode CSRF 403, banner guidance mapping (unit + page), upstream-only 12.5ms render and zero-stays-zero, both-missing note exactly once, settings canonical redirect (unknown dropped, malformed 400 without write), bool yes/no evidence round-trip |
| Updated replay/evidence contracts | PASS | `test_exact_replay_preserves_valid_values` extended with the exact-`client` matcher key; `test_new_selectors_travel_to_evidence_and_links` now asserts `timing_available=yes` (old `True` spelling could not replay through the filter-bar parser) |
| Existing T4a/assistant/traffic suites | PASS | 99 passed across `test_parity_t4a_web.py`, `test_assistant_corrections.py`, `test_assistant_scope.py`, `test_external_client.py`, `test_traffic_api.py` |
| `ruff check` + `ruff format --check` | PASS | Both clean over `app` + `tests` (`--fix` applied to two function-import blocks only; `en.json` kept to its one added key) |
| `uv lock --check --offline` | PASS | No manifest/lock delta: no new dependencies (stdlib urlencoded parsing; `python-multipart` absent) |
| Assets | PASS | `assets/src/js/ask.js` authored (full selector scope, native false/0); served `app/web/static/js/ask.js` synced by the exact `build:js` copy step and `node --check` clean (served tree is gitignored build output, not committed, `.gitignore` unchanged) |
| 120-row fixture / HMAC / 77-rule catalog | PASS | Untouched: no fixture, rule or config changes in tree; new tests use tmp stores only |
| Protected E2E incl. new chat-POST capture test | BLOCKED (environmental) | Chromium fails at launch in this shell sandbox (`TargetClosedError`, Mach IPC `Permission denied` — identical for the two pre-existing tests, so not caused by this change); coordinator executes `uv run --locked pytest tests/e2e/test_parity_t4a.py -q` with the browser sandbox ON (updated `client=` redirect assertion plus new `test_ask_posts_full_trusted_scope` capturing the stubbed outgoing POST with native false/0) |
| Real AI / real acceptance / release | NOT RUN | No production transport, key, account or paid call; no native Linux/release claim; no overall parity/T4 claim; stopping for independent review before T4b1 |

## 2026-11-02 — Parity T4b1 report UI (implementer run)

Owner-authorized bounded T4b1 after reviewed T4a on
`feature/logwerk-parity-2026-11-01` (frozen anchor `6d92231` clean,
prior HEAD preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no subagents, no new approval loop, no
private parent files/logs/keys/history, no provider/product calls, no
live activation/push/main/deploy/allowance reset. Public synthetic
fixtures only; prior work, 120-row fixtures, 77 bot rules, core HMAC,
auth/usage, no-browser-imports/no-translations preserved.

Review-prelude residuals were reproduced against the real code first:
the rendered IP-search form action dropped the selected explorer sort
(backend already preserved it when explicitly supplied), and bounded
`get_report` journeys/journey_entries hit the 1600-char evidence bound
on an ordinary 1-client/1-journey imported fixture while the other 8
reports passed. Both are closed inside this bounded stage: the form
action now carries the allowlisted sort (shared navigation stays
sort-free), and the model-facing quality carries compact journey
limitation notes while full service/API payloads keep the exact
long-form sentences and the 1600-char/65KB bounds are unchanged (no
blanket limit increase, no filter/field loss).

`uv run --locked --offline pytest tests/unit tests/integration`
(1005 passed, 2 skipped — same pre-existing live-loopback category —
exit status visible, no tail-masking) plus focused suites below.

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t4b1_web.py` | PASS | 12 passed: IP-search form action preserves oldest/path_asc sort (parsed query, never leaked into side nav), POST via the rendered action keeps sort with safe pseudonym redirect and no raw IP in the followed page, bounded journeys/journey_entries fit 1600 chars with exact client scope/counts/coverage/limitations while the full service payload keeps the long-form 1800s notes, performance page agrees with service + Bearer API on slow-endpoint totals with server-side avg/p95 ranking and paging through the filtered scope, shared `timing_available=no` filter empties timing honestly, SEO 3xx/4xx/5xx views with exact path/bot drilldowns and supporting-data links, AI-only view with universe counts and absence-not-proof caveat, referrer internal/external SQL narrowing with sanitized full paths and exact-target drilldown, htmx partials serve the same context, and a central-locale-key audit over all six new templates |
| New `tests/e2e/test_parity_t4b1.py` | BLOCKED (environmental) | 2 protected tests collect cleanly (navigation/chart/table/filter/detail, 390/1440 widths, dark theme, keyboard focus, no external requests/console errors); Chromium fails at launch in this shell sandbox (`TargetClosedError` — identical for the pre-existing T4a tests, so not caused by this change); coordinator executes `uv run --locked pytest tests/e2e/test_parity_t4b1.py -q` with the browser sandbox ON |
| Neighbor suites (T4a web/corrections, assistant, traffic) | PASS | 64 passed across `test_parity_t4b1_web.py`, `test_parity_t4a_web.py`, `test_parity_t4a_corrections.py`; full assistant stage-C and export suites green inside the 1005 |
| `ruff check` over `app` + `tests`, `ruff format --check` | PASS | Both clean (unused journey-limitations import removed, implicit-concat parenthesized, touched files formatted); `en.json` kept to new `perf`/`seo`/`ref`/`nav` keys only |
| `uv lock --check --offline` | PASS | No manifest/lock delta: no new dependencies |
| Assets | PASS | `assets/src/js/overview.js` extended with a generic theme-aware bar renderer for the 8 new report charts (every chart keeps a table alternative); served `app/web/static/js/overview.js` synced by the exact `build:js` copy step and `node --check` clean; `node scripts/check_no_external.mjs` reports no external references (served tree is gitignored build output, not committed, `.gitignore` unchanged); two authored lucide-style nav icons (`search.svg`, `link.svg`) |
| 120-row fixture / HMAC / 77-rule catalog | PASS | Untouched: no fixture, rule or config changes in tree; new tests use tmp stores only |
| Gitleaks | NOT RUN | `gitleaks` is not installed in this environment and installs are out of scope (no network, no user-wide changes); the diff adds no secrets, keys, tokens or real logs (synthetic `synthetic-test-*` values only, matching the existing test pattern) |
| Journeys UI (T4b2), saved views/comparison/refresh/Help (T4c), follow/GeoIP (T5), release | NOT RUN | No UI added for journeys/entry paths/security rate sequences, saved views, comparison controls, refresh or comprehensive Help; genuine country UI stays T5a; no overall T4 claim; stopping for independent review |

## 2026-11-02 — Parity T4b1 review corrections (implementer run)

Owner-authorized T4b1 corrections before T4b2 on
`feature/logwerk-parity-2026-11-01` (frozen anchor `319eafb` clean,
prior commits preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no agents/new approval loop, no parent
private files/keys/history/real logs, no actual product/provider
calls, no Docker/live activation/push/main/deploy/allowance reset.
Public/synthetic fixtures only; prior work, 120-row fixtures, 77
bot rules, core HMAC, auth/usage preserved. No browser import, no
translations.

Reproduced first on the frozen anchor with rendered controls and
partial requests: `/performance?sort=p95_desc`, `/seo?view=ai_only`
and `/referrers?relation=external` returned 200 while the
serialized `#filter-bar` (no `sort`/`view`/`relation` inputs) and
the partial `HX-Push-Url` silently fell back to
`avg_desc`/`client_errors`/`all`. The all-URL referrer overview was
absent (404-only page; host-only `top_referrers` did not fill the
gap). Referrer 404 supporting-data links filtered host+target only
(widening different source paths). Tool hrefs still pointed at
Overview/Errors/Crawlers placeholders. Slow-endpoint copy read
generic "Most requests/Requests" for measured-only rows.

`UV_CACHE_DIR=/tmp/uvcache uv run --locked pytest tests/unit tests/integration`
(1016 passed, 2 skipped — same pre-existing live-loopback category —
exit status visible, no tail-masking) plus focused suites below.
`uv lock --check` clean (no manifest/lock delta, no new
dependencies). `ruff check` + `ruff format --check` clean over
`app`/`tests`/`clients`. `npm run build` + `node
scripts/check_no_external.mjs` clean (served `app/web/static/js/*`
is gitignored build output; authored `assets/src/js/*` unchanged;
tracked `app/web/static/app.css` reverted — no CSS source change).
Gitleaks NOT RUN (`gitleaks` not installed; no network installs in
scope; diff adds only synthetic `synthetic-test-*` values, no
secrets/keys/tokens/real logs).

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t4b1_corrections.py` | PASS | 10 passed: filter-bar hidden sort/view/relation, partial Apply preserves `sort=p95_desc`/`view=ai_only`/`view=broken&relation=external` in `HX-Push-Url`, paging/variant links keep page-local state, full referrer URLs (same-host http/https multi-path, ordinary 2xx/304 `/ordinary-source-*`, internal alias `shop.example.org`, missing-referer exclusion, host-only legacy, query-secret absence, unknown-bytes em dash) with service/API/UI agreement, stable paging/filter scopes, token negatives, honest "Related requests" scope labels (no exact-row claim, no `None://` invention), report href replay with contradictory parent status staying empty and exact client travelling, `referrer_urls` tool bounds <=1600, measured-request labels with preserved backend sort |
| Updated `tests/integration/test_parity_t4b1_web.py` | PASS | 12 passed: cross-page nav assertion now allows the active view's canonical sort while every other page link stays sort-free (Requests sort cannot break SEO) |
| Updated `tests/integration/test_assistant_stage_c.py` | PASS | 28 passed: `REPORT_NAMES` allowlist extended with approved `referrer_urls`; evidence hrefs updated to implemented pages (`/seo?view=client_errors`, `/performance?`) |
| New `tests/e2e/test_parity_t4b1.py::test_apply_keeps_page_local_state` | BLOCKED (environmental) | Collects cleanly; Chromium fails at launch in this shell sandbox (`TargetClosedError`, EPERM/kill — identical for the pre-existing tests, so not caused by this change); coordinator executes `uv run --locked pytest tests/e2e/test_parity_t4b1.py -q` with the browser sandbox ON (label updated to "Measured requests (most first)"; 1440/390 both themes, no external requests/console errors) |
| 120-row fixture / HMAC / 77-rule catalog | PASS | Untouched: no fixture, rule or config changes; new tests use tmp stores only |
| Requirements clarification (PAR-03/04/07, accepted full parity) | RECORDED | PAR-03 measured labels now read "Measured requests" (backend ranking/keys/API unchanged, no fake all-traffic count). PAR-04 full sanitized referrer-URL overview added alongside the retained 404-target view (LogWerk `renderRefererUrls` + full-path requirement; `GET /api/v1/referrers/urls`, `get_report referrer_urls`, web `view=all/broken`, stdlib `--endpoint referrer-urls`, `docs/external-api.md`); missing scheme/path reads Unknown, never direct-traffic/people claims. PAR-07 chat-disabled/no-key/offline API still works (focused + full suites green without provider). Tool hrefs now reproduce the executed report (page-local view/sort/relation; contradictory parent filters stay empty; exact client travels). No false full-release/native-Linux/owner-acceptance claim; stopping for independent review before T4b2 |
| Journeys UI (T4b2), comparison halves (T4c), GeoIP (T5), release | NOT RUN | No journey/security UI, no comparison-half link change, no GeoIP, no push/main/deploy; independent review stays required before T4b2 |

## 2026-11-02 — Parity T4b2 journeys/entry-paths/security report UI (implementer run)

Owner-authorized T4b2 after reviewed T4b1 on
`feature/logwerk-parity-2026-11-01` (frozen anchor `7062190` clean,
prior commits preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no agents/new approval loop, no parent
private files/keys/history/real logs, no actual product/provider
calls, no Docker/live activation/push/main/deploy/allowance reset.
Public/synthetic fixtures only; prior work, 120-row fixtures, 77
bot rules, core HMAC, auth/usage preserved. No browser import, no
translations; all new visible text through central `en` keys; no
template/JS metric reimplementation (shared service contracts only).

Scope actually built: `/journeys` page (ranked technical-journey
list with server `sort` × 4 and `min_requests` floor, entry-path
aggregation with complete/partial shares and the outside-window
caveat, opaque-ID timeline detail with bounded chronological rows
and shown/total truncation, all with Chart.js plots plus table
alternatives and exact-path/client drilldowns); expanded
`/security` page (findings chart, 401-challenge note, per-offender
average rate + whole-UTC-minute peak + interval, sample/sequence
tables with shown/total/truncation, offender shown/total counts);
tool evidence maps `journeys`/`journey_entries` to `/journeys` with
the executed sort/min-requests defaults and finding links to
`/requests` (client-scoped for offenders), `/errors` and
`/crawlers` — overview is no longer a fallback. Comparison links,
saved views, refresh and comprehensive Help stay T4c; genuine
country UI stays T5a. Inherited model clarity: `referrer_urls`
evidence now carries `host_sample` rows plus the "host-only
URL-group samples; paths withheld, never host totals" limitation
(same-host/different-path regression; API/UI keep full local
sanitized URL groups; no Referer path/scheme added to egress; no
provider call).

`UV_CACHE_DIR=/tmp/uvcache uv run --locked pytest tests/unit`
(416 passed) and `uv run --locked pytest tests/integration`
(612 passed, 2 skipped — same pre-existing live-loopback
category). `uv lock --check --offline` clean (no manifest/lock
delta, no new dependencies). `ruff check` + `ruff format --check`
clean over `app`/`tests`. `npm run build` +
`node scripts/check_no_external.mjs` clean (tracked
`app/web/static/app.css` rebuilt for the new templates; served
`app/web/static/js/*` is gitignored build output, synced by
`build:js`; `node --check` clean). Gitleaks NOT RUN (`gitleaks`
not installed; no network installs in scope; diff adds only
synthetic `synthetic-test-*` values, no secrets/keys/tokens/real
logs).

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t4b2_web.py` | PASS | 12 passed: journeys list agrees service/API/page (7 journeys, `/gone-1` first by shown requests), all 4 server sorts rank whole scope with invalid rejection, `min_requests` floor (5 eligible) with API agreement, paging + client-pseudonym filter, opaque timeline detail (exact rows, unknown-ID empty state, partial-selector/malformed 400, limit-2 truncation note), entry-paths view (7 groups) with API agreement, security expanded evidence (chart, 401-challenge note, avg/peak/sequence, exact offender counts, path/client drilldowns), support links never overview (`/requests`/`/errors` only), journey evidence hrefs replay on `/journeys` with server defaults, referrer host-only regression (repeated `host_sample`, withheld paths, `never host totals`, <=1600 chars) |
| Updated `tests/integration/test_assistant_stage_c.py`, `tests/integration/test_web_partb.py` | PASS | 2 contract evolutions required by T4b2: journey evidence hrefs now land on `/journeys` with executed scope + fixed defaults (selector-override purpose unchanged); 200 sensitive-path card now links to the Requests explorer that lists its rows (error-group exclusion kept, overview fallback removed) |
| New `tests/e2e/test_parity_t4b2.py` | BLOCKED (environmental) | Collects cleanly; Chromium fails at launch in this shell sandbox (`TargetClosedError` — identical for the pre-existing T4b1 e2e, so not caused by this change); coordinator executes `uv run --locked pytest tests/e2e/test_parity_t4b2.py -q` with the browser sandbox ON (journeys nav/chart/sort/entries/detail, security chart/rates/sequence/401, 390-dark/desktop-light widths, keyboard focus, no external requests/console errors) |
| T4c (saved views/comparison/refresh/Help), follow/GeoIP (T5), release | NOT RUN | Not implemented or claimed; stopping for independent review |

## 2026-11-02 — Parity T4c saved views/comparison/refresh/Help + frozen T4b2 corrections (implementer run)

Owner-authorized T4c after reviewed T4b2 on
`feature/logwerk-parity-2026-11-01` (frozen anchor `4aa3fd0` clean,
prior commits preserved, no amend), exact model
`muse-spark-1.3-contributor` / medium / Contributor ON; sandbox +
approval ON, sole writer, no agents/new approval loop, no parent
private files/keys/history/real logs, no actual product/provider
calls, no Docker/live activation/push/main/deploy/allowance reset.
Public/synthetic fixtures only; prior work, 120-row fixtures, 77
bot rules, core HMAC, auth/usage preserved. No browser import, no
translations; all new visible text/aria/chart/help/errors through
central `en` keys; metrics/filter engine stays shared (no
template/JS reimplementation).

Frozen defects closed FIRST (independent probes at `4aa3fd0`):
`tests/e2e/test_parity_t4b2.py` EXT_LINES used literal backslash-n
bytes (0 accepted, empty journeys chart) — fixed to physical
newlines with `accepted == 12 and rejected == 0` asserted, no
weakened assertions or fake totals; `#filter-bar` now serializes
journey `view`/`sort`/`min_requests` through Apply/native-GET/htmx/
canonical/paging (form-serialization + click-Apply regressions, no
sort leaks to other reports); journey instants render in the
selected display zone with per-instant offset/DST correctness
(URL/API/storage stay canonical UTC) and durations use exact
microsecond labels (`1 µs`, never `0.000 s`); security cards map
`avg_numerator`/`peak_minute_numerator`/`peak_minute_scope` to
central labels with explicit UTC-minute endpoints (tempo prose
kept, internal key names removed from it). Backend exact
microseconds, raw canonical API/URL values, all 11 bounded model
reports and trusted-client/`<=1600`-char/strict-body/exact-IP/
privacy invariants preserved.

Scope actually built: session-owned saved views (per-user CRUD with
CSRF, allowlisted local report paths, validated safe filters, no
arbitrary redirects/source paths/keys/raw IP in stored URLs,
bounded names/counts, TZ/filter-reset/path_exact preserved);
explicit current-vs-baseline `/comparison` page (shared comparison
service + validated API, same filters/both scope+coverage, zero/
empty honesty, meaningful chart + table, reproducible canonical
links) with no silent baseline default; opt-in OFF-default
visibility/focus-aware read-only refresh of IMPORTED data (finite
interval set, never import/AI/network, pause while editing/modal,
no full-IP caching); comprehensive Help (formats + CLI-only
ingestion, timing/cache/304, bot claims/SEO absence/referrer
privacy, journeys/partial coverage, IP modes/key separation/lost-
key/exact-spell search, exports/limits/metadata, saved views/
comparisons/refresh, independent API + curl/n8n, GeoIP
Unknown/licensing readiness, explicit follow-CLI-off-until-T5);
central-English locale readiness (date/number consistency, no
language chooser). Model comparison evidence now links to the
ACTUAL executed current half + baseline half with same
selectors/client (validated explicit UTC values, both coverage;
unsplittable parents link with no silent baseline; model cannot
choose an outside window via link defaults). All new report maps
resolve to real pages (comparison → `/comparison`).

`uv run --frozen pytest tests/unit tests/integration -q
-p no:cacheprovider`: 1053 passed, 2 skipped (pre-existing
live-loopback skips). 9 version-tuple assertions legitimately
extended `(1..5)` → `(1..6)` / `(5,)` → `(5, 6)` for the new
`0006_saved_views.sql` migration (data-preservation intent
unchanged; saved-views table is new and empty). `ruff check` +
`ruff format --check` clean over `app`/`tests`/`clients`.
`npm run build` + `node scripts/check_no_external.mjs` clean
(new `scale`/`bookmark` icons vendored with provenance; served
`app/web/static/js/*` is gitignored build output, synced by
`build:js`; `node --check` clean). `uv lock --check --offline`
clean (no manifest/lock delta, no new dependencies). Gitleaks NOT
RUN (`gitleaks` not installed; no network installs in scope; diff
adds only synthetic `synthetic-test-*` values, no secrets/keys/
tokens/real logs).

| Check | Result | Evidence |
| --- | --- | --- |
| New `tests/integration/test_parity_t4c_web.py` | PASS | 25 passed: journey form-serialization + partial/canonical retention, Berlin 13:00 +01:00 vs UTC 12:00 +00:00 with canonical UTC in titles/selectors, `1 µs` duration (no `0.000 s` cell), central security labels with no raw enum/repr, saved-view create/open/rename/update/delete roundtrip, CSRF 403 incl. Unicode (no 500), per-user ownership (foreign ids 404), hostile targets rejected (no stored csrf/next/raw-IP/redirect), Unicode names + 50-view bound, previous/explicit comparison matching service counts with canonical links, zero-baseline exactness (no Infinity), empty-current honesty (no confident ratio), unequal/hostile baseline 400, no-baseline explicit prompt, model-halves evidence replay with equal counts (tampered halves 400, odd parent honest), refresh OFF-default + read-only + 405 on POST, locale key/placeholder audit incl. dynamic families, no language chooser, chat-independent comparison API, Help sections + no import controls |
| New display-helper unit tests | PASS | Berlin CET/CEST per-instant offsets incl. spring-forward gap pair, UTC rendering, unparsable fallback verbatim, duration ladder 0/1/999µs–ms–s with 1µs exact |
| New `tests/e2e/test_parity_t4c.py` + fixed `tests/e2e/test_parity_t4b2.py` | BLOCKED (environmental) | Both collect cleanly; Chromium fails at launch in this shell sandbox (`TargetClosedError`, EPERM/kill — identical for pre-existing T4a/T4b1 e2e, browsers installed at `artifacts/playwright-browsers`, browser sandbox kept ON, no weakening); coordinator executes `uv run --locked pytest tests/e2e/test_parity_t4c.py tests/e2e/test_parity_t4b2.py -q` (T4c: actual Apply-kept journey state, Berlin instants, security labels, bookmark roundtrip, previous comparison chart/table, refresh opt-in toggle, Help, 1440/390 both themes, keyboard focus, no external requests/console errors; T4b2: same flow with 12-accepted fixture assert) |
| Full maintained E2E | BLOCKED (environmental) | Same sandbox launch block; same coordinator command covers `tests/e2e` |
| Follow/real-GeoIP/native-Linux/model-checks/owner-acceptance | NOT RUN | Not implemented or claimed; stopping for independent review |

## 2026-11-02 — Parity T4c independent-review corrections (Muse-only run)

Owner-authorized bounded T4c corrections ONLY (no T5a), after the
frozen independent review `artifacts/task-inputs/parity-t4c-independent-review.txt`
plus `parity-t4c-warm-review.txt` as repro data (not authorization).
Same protections: exact model `muse-spark-1.3-contributor` / medium /
Contributor ON, sole writer, no subagents/new approval loop, current
public/synthetic workspace only, no parent private files/keys/logs/
history/Docker/product/provider calls/allowance resets/push/main/
deployment. No UI import, no translations; all commits, 120-row
fixtures, 77 rules, core HMAC/auth/usage preserved; no T5a claim or
paid call. All six confirmed findings closed with reproductions:

1. Save-current replays the displayed canonical validated state
(global client + page-local filters): `filter.js` updates the
`#save-view-target` hidden input from the server-issued `HX-Push-Url`
only on 2xx `#page-content` responses; failures retain the last
displayed state; canonical builder still emits no CSRF/raw-IP.
2. Comparison previous/custom baselines survive `#filter-bar`
serialization/Apply/native-GET/htmx/HX-Push/refresh via canonical
hidden baseline state; absent baseline still renders the explicit
choice with no default/widening; explicit controls retained.
3. Shared `_utc_input` UTC formatter: offset-free valid
`datetime-local` values with dividing steps, minute-only form kept
where exact, nonzero seconds/microseconds retained (1us incl.
+/-offset equivalent instants); unchanged global Apply no longer
floors fractional/seconds evidence windows; URLs/API stay canonical
aware UTC; backend 1us/gap semantics untouched.
4. Refresh shows central ON/OFF state immediately on check/uncheck,
re-reads the last successfully applied state via GET-only fragment
requests, pauses (honest central paused note) on unapplied drafts —
never sending them — and stays silent-paused while hidden/modal/
focused; no hardcoded English fallback (server-rendered central
attributes, initial-text fallback); OFF default, finite intervals,
all selectors/baselines preserved, no stale private-IP DOM.
5. Saved-view update is now a real owner-only UI control per owned
view (prefilled validated target, CSRF, per-user ownership, human
labels); templates still create/rename/delete.
6. Saved-view path ids bound to positive signed SQLite 64-bit
(`_checked_view_id`) before DB binding for rename/update/delete:
max-boundary/zero/negative/overflow/overlong-digit/non-numeric ids
answer the fixed missing-view 404 with no exception/path/SQL text
and no DB mutation; unauthorized/CSRF/foreign boundaries and the
16 KiB body bound kept; no blanket catches; `read_store`
type-discrimination untouched.

One pre-existing assertion legitimately evolved (not weakened):
`test_preset_window_prefills_normalized_values` now accepts valid
offset-free seconds/fractional prefills for live `now`-anchored
presets (the mandated no-flooring contract); the sibling minute-exact
custom-window assertions still pin the minute-only form.

| Check | Result | Evidence |
| --- | --- | --- |
| `tests/integration/test_parity_t4c_web.py` + `test_web_corrections.py` | PASS | 33 passed in T4c file (25 prior + 8 new: formatter precision incl. 1us and offset-equivalent instants, fractional global Apply round-trip, valid UTC baseline controls, baseline survival through partial push + hidden state for previous/custom with no-baseline honesty, save-target canonical header + replay, UI update form + retained filters + hostile 400, id-bound units + 3x6 HTTP 404 probes with fixed message/no-leak/no-mutation + preserved 403 gate, central refresh messages + no hardcoded English in `refresh.js`); corrections-file preset assertion evolved for the no-flooring contract |
| `tests/unit tests/integration` clean AND conflicting (`AI_ENABLED=true LLM_WARN_AT_USD=999`) | PASS | 1061 passed, 2 skipped (pre-existing live-loopback skips) in each configuration, actual exit statuses observed (`--junitxml` run, no pipe masking) |
| `ruff check .` + `ruff format --check .` + `uv lock --check --offline` | PASS | All checks passed; 203 files already formatted; 42 packages resolved, no manifest/lock delta |
| `npm run build` + `node scripts/check_no_external.mjs` + `node --check` | PASS | Vendor/js/css rebuilt; no external references in served assets/templates; served `app/web/static/js/*` remains gitignored build output; tracked `app.css` byte-identical after rebuild (no new classes) |
| `tests/e2e/test_parity_t4c.py` (3 new: real Apply→Save→Open incl. failure-retained state, baseline Apply + true `input.value` for both modes, fake-clock refresh past 30s asserting URLs/methods/default/dirty+hidden+modal+focus pause and resume; prior refresh-toggle assertion kept, not relaxed) | BLOCKED (environmental) | Collects cleanly (6 tests); Chromium fails at launch in this shell sandbox (`TargetClosedError`, Mach-port `Permission denied`, kill EPERM — identical to the pre-existing T4a/T4b1/T4c block, browser sandbox kept ON, recorded once, no retry/weakening); coordinator runs `uv run --locked pytest tests/e2e/test_parity_t4c.py -q` outside the sandbox |
| Prior PASS boundaries | PASS | All 11 bounded reports `<=1600`/trusted-client, host-only referrer URL groups with paths withheld, exact-IP search/private modes/chunk body cap, journey Apply/TZ/microduration/semantic SQL, privacy/model-budget scope — covered by the unchanged green suites above |
| T5a, release, owner acceptance | NOT RUN | Not implemented or claimed; independent review of these corrections stays pending |

## T5a offline GeoIP (PAR-09) + T4c inflight completion — 2026-11-02

Worktree continuation on `feature/logwerk-parity-2026-11-01` (prior HEAD
`abdf69a` preserved; no reverts). Corrected dependency fact: the earlier
"upstream 3.2.0 ships cp312-only wheels" claim is FALSE — the current
`uv.lock` itself carries cp312/cp313/cp314/cp315 wheels and official
metadata reports `Requires-Python: >=3.10`, Apache-2.0. The temporary
`python_full_version < '3.14'` marker was an offline-cache workaround
only; it is removed and `maxminddb==3.2.0` is pinned unconditionally
(`uv lock` + `uv export` + `uv sync --frozen` regenerated offline).
Runtime tested is 3.12.16 only; 3.14 runtime is not claimed.

Corrected warm issues before claiming done: `CountryLookup.open` now
accepts ONLY the genuine `DBIP-Country-Lite` database type (any other
family closes its handle and reports unavailable — never mislabelled
MaxMind provenance or a wrong license); `is_lookup_eligible` explicitly
excludes reserved/private/loopback/link-local/unspecified/
documentation/multicast even when `is_global` is true (`4000::1` is
reserved AND global; IPv4-mapped documentation covered); `refresh.js`
adopts each swap's OWN originating-request state via `detail.xhr`
(no FIFO, no live-form fallback); overview country drilldown links,
requests-page credit, and the exact-credit allowlist in
`check_no_external.mjs` added; stale cp312-only wording in
`THIRD_PARTY_NOTICES.md` corrected. No genuine MMDB file is in Git
(structural test) or the Contributor context; no IP/HTTP lookup, no
invented hash-to-country map, no browser import UI, no translations.

| Check | Result | Evidence |
| --- | --- | --- |
| `tests/unit/test_geoip.py` (new, 44) | PASS | Record-shape allowlist (`country_code` + nested `iso_code`, `ZZ`/wrong-type/length rejection), shared selector (`us`→`US`, `UNKNOWN`, `""`/`XX1` reject), eligibility matrix (reserved `4000::1`, IPv4-mapped doc/global, CGNAT, link-local, multicast, unspecified), pre-DB blocking, hit/unknown/unavailable, wrong-type close + no leak, open-gating (missing/dir/garbage), provenance/close/cache/context-manager, no-MMDB-in-tree |
| `tests/integration/test_parity_t5a.py` (new, 10) | PASS | Hand-derived 6-row import (US 3/0/2/3300, AU 1/1/0/500, Unknown 2/0/0/150; coverage 4/2/0) with service/API/export/AI/saved-view selector equality, hostile `XX1` 400 without echo, blank-dropped saved views, unavailable graceful + required `geoip_unavailable:database_required` with zero writes, corrupt-file unavailable, reprocess 4-row enrichment with stable core IDs/HMAC then 0-row idempotent rerun, no-original-egress across API/exports/countries, CLI env/flag precedence |
| Existing suites updated for the mandated T5a contract (not weakened) | PASS | Migration tuples `(1..7)`/`(5,6,7)` + new 0007 column/index assertions; row-key sets gain the 4 safe country fields (`test_traffic_api`, `test_owner_ux_stage_b`); matchers contract gains `country: None` (`test_t8_preparation`); overview locality now allowlists exactly the mandated `https://db-ip.com` credit anchor |
| `tests/unit tests/integration` clean AND `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 1115 passed, 2 skipped (pre-existing live-loopback skips) in EACH configuration, exit codes observed separately via saved status before any tail/echo |
| `ruff check` + `ruff format --check` repo-wide + `uv lock --check --offline` | PASS | All checks passed; 157 files already formatted; 43 packages resolved, no manifest/lock delta |
| `npm run build` + `npm run check:external` | PASS | Vendor/js/css rebuilt (`refresh.js` XHR-keying shipped to ignored static output, tracked `app.css` rebuilt); external check passes with the single mandated credit `href` allowlisted — all `src`/`fetch`/`import`/`url()` and every other `href` still fail |
| `tests/e2e/test_parity_t4c.py` + `tests/e2e/test_parity_t5a.py` (new: inflight reversal + error-while-other-succeeds; country breakdown/drilldown/select/saved-view/Ask) | BLOCKED (environmental) | Both collect cleanly (8 + 3 tests); Chromium fails at launch in this shell sandbox (`TargetClosedError` — same class as the pre-existing T4a/T4b1/T4c block, browser sandbox kept ON, new attempt recorded once, no retry/weakening); coordinator runs the protected suite plus the genuine-DB runtime proof after freeze |
| Genuine MMDB runtime lookup, T5b, release, owner acceptance | NOT RUN | Not implemented or claimed; coordinator-owned mount + protected full rerun and independent review stay pending |

## T5a independent-review corrections (residuals 1–5) — 2026-11-02

Worktree continuation on `feature/logwerk-parity-2026-11-01` (prior HEAD
`31af5eb` preserved; no reverts, no T5b, no release/acceptance claims).
All five frozen-review residuals closed without redoing the proven
genuine pipeline (no MMDB copied here; coordinator reruns the actual
file proof after freeze). `maxminddb==3.2.0` stays unconditionally
pinned/locked; no artificial version marker restored. 120
fixtures, 77 rules, core HMAC/auth/usage and prior commits preserved.

| Check | Result | Evidence |
| --- | --- | --- |
| Residual 1: stale auto/OOB cancel + save-canonical honesty | PASS (unit/integration) / browser PENDING | `refresh.js` cancels a superseded automatic response in `htmx:beforeSwap` (`shouldSwap=false`: main, OOB and history skipped together) when the accepted state moved past it or the live form holds drafts; explicit Applies always swap in arrival order with own-XHR state; `tick()` sends only the accepted state (no live-draft fallback); `filter.js` moves the save target to accepted swaps only with the shared stale marker; `f-country` joins the OOB set; reversal test now asserts the newer explicit Apply wins (POST/401 preserved, save/canonical moved, next tick replays scope) with the error leg dispatching the clean held tick before the draft/fail Apply; draft-only test covers search/method/status/TZ/country with no implicit apply; only expected 400/500 diagnostics segregated |
| Residual 2: DB-IP credit everywhere + travelling provenance | PASS | One shared `partials/geo_credit.html` (exact plain anchor) included via the filter bar on all 10 data pages (+ Ask); per-page duplicates removed; export envelope gains `geo` + full `attribution` (text/url/database/license), CSV gains `X-Logcarve-Export-Geo`; client JSON/CSV summaries surface both; streaming snapshot, row-count, strict grammar, formula defense, 0600 and exclusive-create limits unchanged |
| Residual 3: honest Unknown/provenance copy | PASS | `geo.no_database` ("No country database is configured…") removed; Unknown-only selections show `geo.no_source_in_selection`, stored-without-DB/legacy scopes show `geo.stored_without_database` with counts, coverage line gains `legacy`; "Server-country estimate" renamed to client-address country estimate computed locally (locale keys, `LIMITATIONS_GEO`, Help, API docs); Help keeps the pinned "honestly shows Unknown" phrase with selection-scoped wording |
| Residual 4: exact-anchor asset guard | PASS | `check_no_external.mjs` allowlists ONLY the exact plain `<a href="https://db-ip.com">` (tag-checked, every href on a line scanned); credit-as-stylesheet/image/script/preload, mixed credit+evil lines and all other remote vectors still fail; `node --test scripts/check_no_external.test.mjs` 9/9 green (synthetic temp fixtures, no external HTTP); CSP/local-asset checks untouched |
| Residual 5: country cross-consumer report | PASS | Typed `get_report(report="countries")` via shared `country_breakdown` (aggregate-only projection with exact counts, top-5/remainder, coverage, credit; ≤1600-char / 65 KiB bounds intact; scope client+country override enforced); evidence href replays the Overview `#country-h` section with same filters/window/client/country; CLI gains `countries` endpoint + validated `--country` (ISO/UNKNOWN) for report fetch/export with default `all` still baseline-only; local Chart.js country plot alongside the accessible table; no fixture changes; 11 prior reports/projections/budget controls preserved |
| `tests/integration/test_parity_t5a.py` (+7), `tests/unit/test_client_strictness.py` (+4), `test_assistant_stage_c` + `test_parity_t3` + `test_api_country_filter_export_and_attribution` (mandated contract extensions, not weakenings) | PASS | All-page credit (exactly one anchor per page), chart canvas/data + OOB country select, Unknown-only and stored-without-DB copy, JSON envelope + CSV-header geo credit, typed/bounded/linked AI countries report with hostile scope override, CLI countries/`--country`/export forwarding, JSON/CSV provenance carry incl. malformed-header failure, full attribution shape with license/database, header fixture with geo/attribution, 12-report allowlist |
| `scripts/check_no_external.test.mjs` (new) | PASS | 9/9: allowed anchor, credit-as-stylesheet/image/script/preload failures, credit+evil same-line failure, evil-after-credit failure, CSS-import/`url()`/`fetch`/remote-`src`/remote-`href` failures, local/banner passes, temp-file fixture scan without network |
| `tests/unit tests/integration` clean AND `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | 1126 passed, 2 skipped (pre-existing live-loopback skips) in EACH configuration, exit codes captured before any tail |
| `ruff check` + `ruff format --check` repo-wide + `uv lock --check --offline` | PASS | All checks passed; 207 files formatted; 43 packages resolved, no manifest/lock delta |
| `npm run build` + `npm run check:external` + `node --test` guard | PASS | Vendor/js/css rebuilt (stale-cancel + accepted-save + country chart shipped to ignored static output, tracked `app.css` rebuilt); no external references; 9/9 guard tests green |
| `tests/e2e/test_parity_t4c.py` + `tests/e2e/test_parity_t5a.py` (updated reversal + draft-only TZ/country; new every-page credit test) | BLOCKED (environmental) | 12 tests collect cleanly (8 + 4); no new browser launch attempted in this shell sandbox (known `TargetClosedError` block recorded once before, browser sandbox kept ON, no retry/weakening); coordinator runs the protected suite plus the genuine-DB runtime proof after freeze |
| Genuine MMDB runtime lookup, T5b, release, manual acceptance | NOT RUN | Not implemented or claimed; coordinator-owned mount + protected full rerun and independent review stay pending |

## T5b1 timestamp compatibility + numeric domain — 2026-11-02

Owner-authorized T5b slice 1 (follow/rotation T5b2 and
activation/benchmark helpers plus documentation closeout T5b3
explicitly NOT started), implemented solely by Muse Spark 1.3
Contributor (medium, Contributor ON) with sandbox + approval ON:
sole writer, no subagents, no extra approval loop, no parent
files/keys/private history, no product/provider calls, no
Docker/live activation/push/main/deployment. All application/test
changes by the implementer on `feature/logwerk-parity-2026-11-01`
(prior HEAD `016b458` preserved, no reverts, no amend). The 120
fixtures, 77 bot rules, core HMAC/auth/usage/spent ledger and prior
commits preserved; no browser import UI, no translations. The two
frozen-review browser-harness defects were fixed first without
touching product policy: the T4c error leg now runs under one
phase-aware route handler (exactly one fulfillment per route, never
unrouted while a held route is alive; newer-Apply/POST/401/Save/
canonical/failure-leg assertions unchanged), and the T5a Unknown
browser test now asserts the actual stored-Unknown
`no_source_in_selection` copy with the exact `0/4/0/0` coverage
line (never the stored-while-unavailable past fact, never a claim
about the configured database). No fake countries, no weakened
assertions; five application residuals untouched.

| Check | Result | Evidence |
| --- | --- | --- |
| Declared custom timestamp modes (`combined`/`iso8601`/`epoch_s`/`epoch_ms`) | PASS | `time_format` validated at spec load (unknown names fail `interrupted:custom_invalid`); strict ISO (`T`, mandatory `Z`/offset, 1–9 fraction digits, truncation to µs documented), plain epoch grammar (no sign/exponent/non-finite, token-width + instant-range bounds, epoch always `+0000`); naive/host-TZ/locale guessing impossible; UTC-canonical storage so equivalent spellings (`Z`/`+00:00`/shifted offsets/epoch units) share one instant; non-default mode joins the definition fingerprint while absent/`combined` digests keep legacy identity (`t1b.1` unchanged) |
| Byte domain `0..2**63-1` (presets/custom/autodetect/reprocess) | PASS | `normalize_bytes_value` validates ASCII-digit syntax + 19-char bound BEFORE conversion (5000-digit tokens cannot crash or bind; `-`→None, `0`→0, max boundary imports, `2**63`/signed/decimal/unicode/empty reject `invalid_bytes`; absurd tokens trip the pre-existing field budget first with `oversized_field`); no echoed token; single fixed rejection + valid continuation on the same import |
| Exact split-half byte sums | PASS | Every `SUM(bytes)` site aggregates high/low 32-bit halves and combines them in exact Python integer arithmetic (single scan, no float, SQLite `integer overflow` unreachable for importable data); ordinary totals exact ints end to end, and a true total of `2**64+2**63+4` across max-boundary rows returns exactly (service, API envelope, top-paths, countries, comparison, egress projection all observed); per-row storage still nullable int64; referrer all-NULL groups keep the pre-existing `None` contract |
| Fractional compatibility (journeys/edges/sorts/windows/reprocess) | PASS | Custom-ingested `1800.000000 s` gap continues one journey while `1800.000001 s` splits into two (exact `epoch_micros` gap/edge/sort, `duration_us` exact); canonical storage + reprocess idempotence verified (mismatch/unparseable zero, stored instants byte-identical); 1 µs evidence window round-trips through the UTC `datetime-local` controls (`value` keeps `.000001`, `step="0.000001"`, canonical URLs) with exact request counts — T4c `_utc_input` preserved, no duplication |
| `tests/unit/test_parity_t5b1.py` (new, 53) + `tests/integration/test_parity_t5b1_ingest.py` (new, 7) | PASS | Hand-derived instants/offsets/epoch values and int64 edge totals; mode acceptance/rejection matrix, fingerprint identity split, journey 1800±1 µs, reprocess, sums beyond int64 via service + API + comparison + egress, fractional-window web roundtrip |
| Full suites default AND `AI_ENABLED=true LLM_WARN_AT_USD=999` | PASS | Unit 517 passed + integration 669 passed, 2 skipped (pre-existing live-loopback skips) in EACH configuration, exit codes observed separately via saved status before any tail/echo |
| `ruff check` + `ruff format --check` repo-wide + `uv lock --check --offline` | PASS | All checks passed; 159 files already formatted; 43 packages resolved, no manifest/lock delta (no new dependencies) |
| `npm run build` | NOT RUN (not needed) | No authored-asset change in this slice (JS/template revert kept; `app.css` untouched); build stays for the next slice that ships authored assets |
| Protected browser E2E (`test_parity_t4c.py` reversal, `test_parity_t5a.py` Unknown) | BLOCKED (environmental) | Both harness files compile cleanly and collect; Chromium cannot launch in this shell sandbox (known block, browser sandbox kept ON, no retry/weakening); coordinator reruns the protected suite after freeze, including the two corrected expectations |
| Gitleaks fresh run here | NOT RUN (no binary) | No `gitleaks` binary in this environment; reviewed independent-review finding recorded: commits `31af5eb..016b458` report ONE reviewed false positive — `generic-api-key` fingerprint `016b45874418397c13381be6c56bbe5a58` at `tests/integration/test_parity_t5a.py:574` is a `monkeypatch.setenv SESSION_SECRET` short local test label inside `test_unavailable_selection_copy_names_stored_rows` (temporary synthetic TestClient), not an actual provider/session credential; existing `docs/technical-spec.md:787` cost-heading false positive historically known; no broad allowlist, no history rewrite. Coordinator runs Gitleaks with fully redacted output before first public push |
| T5b2 follow/rotation, T5b3 helpers/closeout, release, manual acceptance | NOT RUN | Not implemented or claimed; independent review stays required |

## T5b2 follow/rotation + T5b3 helpers/readiness/docs — 2026-11-02 (consolidated implementation pass)

Owner-authorized continuous pass on `feature/logwerk-parity-2026-11-01`
(prior HEAD `985d363` preserved; three inherited dirty correction files
plus two inherited test files inspected and continued, never discarded).
Sole writer: exact Muse Spark 1.3 Contributor, medium effort,
Contributor ON, no subagents, sandbox + approval ON. No pushes, no main
changes, no Docker/live activation, no paid model calls, no keys read,
no parent/private history, no real logs, no global settings,
no cron/LaunchAgent/service or background watcher. Tree left clean at
`a335f66` (T5b1c), `a6976df` (T5b2), `886ddbf` (T5b1b). Only new/changed
focused tests were run during development; full clean/conflicting
suites, protected browser launches, secret scans and whole-project
reviews were deliberately NOT repeated per stage — the coordinator runs
ONE consolidated final verification after freeze (see pending row).

| Check | Result | Evidence |
| --- | --- | --- |
| T5b1c replay private-association guard (`app/db/importer.py`, shared `repositories.find_core_mismatches`) | PASS (focused) | `tests/integration/test_parity_t5b1c_private_replay.py` (new, 2): transient same-length mutation between fingerprinting and reading attaches no mismatched original (`private_rows=0`, `originals_skipped_mismatch=1`, stored core/HMAC/ID/SHA intact, T6 mismatch warning present) while a matching replay with capture stores one original whose decrypted address matches the stored HMAC |
| T5b1b corrections kept green | PASS (focused) | `tests/unit/test_parity_t5b1b_corrections.py` + `tests/integration/test_parity_t5b1b_corrections_ingest.py` with the replay file: 30 passed |
| T5b2 follow engine (`app/db/follow.py`, migration 0008, CLI `follow`/`replay-archive`) | PASS (focused) | `tests/unit/test_parity_t5b2_follow.py` (new, 10) + `tests/integration/test_parity_t5b2_follow_restart.py` (new, 15): line-splitter partial/oversized-once/`\r`/seal semantics, honest generation labels, live-gzip refusal with zero writes, ambiguous-adoption refusal vs `--fresh-start`, restart taint with stored-row preservation, bounded coverage sample with exact SQL-SUM aggregates and truncation flag, append across polls + crash-after-commit + partial-reread restarts with zero duplication, rename-and-create old-FD tail drain into generation 2, copytruncate fast regrowth, replacement new generation, plain archive full replay (0 inserted/N replayed), gzip archive equivalence, tail-only archive inserts, prefix-mismatch refusal with zero writes, no-sealed-generation refusal, batch-prefix adoption (attempt provenance, offset continuity), capture privacy (checkpoints carry no addresses), writer-busy retry, source escape/symlink refusal |
| Coverage import-history bound (`queries.coverage` + `service`) | PASS (focused) | Same suites plus unit bound test (LIMIT 200 sample, `imports_truncated`, unchanged ASC order, SQL-SUM aggregates); service `_warnings` notes truncation; `coverage_summary` envelope gains the flag (additive) |
| T5b3 `/readyz` schema gate (`app/api/app.py`, `app/api/deps.py`) | PASS (focused) | `tests/integration/test_parity_t5b3_readiness.py` (new, 4): upgraded store 200 with `schema_version` 8; MAX-8-but-incomplete store (dropped table/column) 503 `not_ready` with matching `request_id`; outdated-MAX store 503; missing store creates no files |
| T5b3 upgrade helper (`scripts/upgrade_demo.py`) | PASS (focused) | `tests/integration/test_parity_t5b3_helpers.py` dry-run (no changes), v7→v8 with seeded events/auth/spend/allowance (verdict `upgraded`, applied `[8]`, identical core-event hash, ledger/auth intact, protected backup written), posture refusals (model key, missing IP key); real runs rehearsed on synthetic stores only |
| T5b3 benchmark (`scripts/benchmark_synthetic.py`) | PASS (focused smoke) | 2500-row deterministic smoke: verdict `match`, expected==observed (2498/2 accepted/rejected, slow/404 counts, replay 2498, streamed export 2498 rows); 100k/1M runs are coordinator-owned (NOT RUN here) |
| T5b3 UI/docs | PASS (focused) | `tests/integration/test_parity_t5b3_ui.py` (new, 2): Ask hides Save/Refresh, keeps scope controls; Overview keeps both. Country copy corrected (eligible public-client lookup; never HMAC/private/reserved/docs/identity/residence/proven-bot), Lucide count corrected to the 20-icon vendor PROVENANCE authority, follow Help updated to the implemented CLI, `/readyz` + coverage-flag + deployment-helper docs current |
| `ruff check` + `ruff format --check` on changed files | PASS | All checks passed on the 9 changed/new Python files; scripts `sh -n` clean (`shellcheck` binary absent) |
| Full unit/integration suites (clean AND conflicting env) | NOT RUN | Implementer ran focused files only per the consolidated-pass authorization; coordinator runs the full suites once after freeze |
| Protected browser E2E (repeatable Playwright) | BLOCKED (environmental) | No new browser launch attempted in this shell sandbox (known Chromium-launch block, browser sandbox kept ON); coordinator runs the protected suite after freeze |
| Gitleaks (tracked export + history, fully redacted) | NOT RUN (no binary) | Findings recorded from the reviewed record with one verified correction: the `generic-api-key` fingerprint at `tests/integration/test_parity_t5a.py:574` is a synthetic `SESSION_SECRET` fixture value (test-only dataflow, no secret printed); the commit-SHA component verifies as `016b458744e33713980b081e7c31c6c56bbe5a58` via `git rev-parse 016b458` (earlier notes transcribing it differ and are superseded); `docs/technical-spec.md:787` cost-heading false positive stands; no allowlist, no history rewrite. Coordinator runs the redacted scan before first public push |
| Genuine MMDB runtime lookup, 100k/1M measured runs, fresh-container/offline/runtime checks, conflicting-env regressions, independent changed-boundary probes, independent security/release review, owner acceptance | NOT RUN | Not claimed; coordinator-owned after freeze. Historical model AI-02 stays two of three complete (exhausted allowance, owner acceptance, native x86 verification remain visible). Native Linux x86-64 stays NOT RUN; ARM-host amd64 image runs are EMULATED proof only (distinct arch-tagged images, `verify_candidate.sh` asserts the container arch) |

## Final correction pass — 2026-11-02 (from clean `d753ed5`)

One continuous pass, sole writer, exact Muse Spark 1.3 Contributor /
medium, protections ON, no agents. No pushes, no main changes, no
Docker/live activation, no provider calls, no allowance reset, no
parent/private data, no live data access. Only focused
changed/previously-failed modules ran during the fix; no full
suite/whole protected browser loop per item — the coordinator runs
the final consolidated rerun plus runtime/scale/activation proofs.

| Check | Result | Evidence |
| --- | --- | --- |
| T5b2 follow A: partial-line cursor (`app/db/follow.py`) | PASS (focused + probe) | New `tests/unit/test_parity_t5b2_follow_corrections.py::test_partial_line_within_one_run_exact_offset_and_digest`: first-40-bytes poll then rest, 1 accepted / 0 rejected / 1 row at offset 0, checkpoint at exact file length, digest equals SHA-256 of raw bytes |
| T5b2 follow A: multi-read oversized + rotation tails | PASS (focused + probe) | Same file: 3083-byte oversized line across 1024-byte polls rejects exactly once (`oversized_line: 1`) with digest of all 3168 bytes; probe also covered rotation with a pending tail (gen1 sealed at 30 with 1 rejection, gen2 at 89 with 1 event) |
| T5b2 follow B: replay idempotency (`hash_floor`) | PASS (focused + probe) | `test_repeated_archive_replay_stays_completed_plain`: replay1 and replay2 both `completed` with 0 inserted / 1 replayed, 2 stored events; probes covered gzip replay twice, adopted-prefix replay, and rejected-tail replay (all `completed`, no `archive_prefix_mismatch`) |
| T5b2 follow C: stale CAS (`follow:stale_generation`) | PASS (focused + probe) | `test_stale_concurrent_follower_refuses_without_rewind`: nested full consume wins, outer fails with the fixed stale code, 101 events, checkpoint at the inner total (no rewind), 1 generation; concurrent first-registration guarded the same way |
| T5b2 follow D: live attempt accounting | PASS (focused) | `test_active_generation_reports_running_attempt_counts`: active generation `imports` row carries real totals (`running, 5, 5, 0, 5, 0`) before any seal; idle polls still write nothing |
| T5b2 follow regressions | PASS (focused) | `test_parity_t5b2_follow.py` + `test_parity_t5b2_follow_restart.py` + new corrections file: 30 passed (splitter tests updated to the new feed/seal return shape, assertions preserved) |
| Upgrade helper: legacy core + schema-4→8 (`scripts/upgrade_demo.py`) | PASS (focused) | `test_upgrade_v4_to_v8_with_actual_enrichment` (new): true v4 store from migrations 1..4 with parser-derived rows → `upgraded`, applied `[5, 6, 7, 8]`, core hash preserved, per-fixture enrichment 3 matched / 3 enriched / 0 skipped, `format_id` + `t1b.1` policy set, `duration_ms` still NULL, ledger/auth/holds intact, 0600 backup |
| Upgrade helper: honest failure + preflight | PASS (focused) | `test_upgrade_changed_fixture_fails_loudly_without_restore` (verdict `failed`, backup retained at v4, live at v8, no restore) and `test_upgrade_preflight_fails_before_any_write` (bad IP key on dry-run: posture refusal, no backup dir, schema still 4) |
| Benchmark honesty (`scripts/benchmark_synthetic.py`) | PASS (focused smoke) | 2500-row smoke `match`: streamed SHA-256, `peak_rss_import_mib` + `peak_rss_overall_mib` labeled separately, cursor-level `export_stream_proof`, and an executed authenticated HTTP 413 probe (`export_413_probe.exercised: true`, `export_too_large`) — never a flag derived from row count |
| Ruff + format, exits kept separate | PASS | `ruff check .` exit 0 (`All checks passed!`), `ruff format --check .` exit 0 (221 files formatted); inherited T5b1b import-order + FLY002 + format findings fixed |
| Stale migration-count/help expectations | PASS (focused) | Version tuples updated to `(1..8)` / `(5, 6, 7, 8)` with core/storage/privacy/retention assertions untouched; help now asserts the implemented opt-in CLI follow wording (`logcarve-import follow`, `no live watcher`) instead of `not enabled in this release` |
| Readiness preflight columns (`app/api/deps.py`) | PASS (focused) | Now covers the explorer/export `requests` metadata (cache, timings, policy, country) plus `log_sources.allowed_hosts`; new `test_readyz_rejects_forged_max_missing_query_columns`: forged MAX-8 without `cache_status`/`request_time_ms`/`policy_version` → `schema_supported` false and `/readyz` 503 `not_ready` |
| Focused rerun of all touched/previously-failed modules | PASS (focused) | 182 passed across 12 unit/integration files |
| Full consolidated suite, protected browser E2E, Gitleaks, 100k/1M + runtime/activation proofs | NOT RUN | Coordinator-owned after freeze; no success claimed beyond the focused evidence above |

## Bounded correction — 2026-11-02 (oversized-line discard marker, from clean `7f0c20d`)

One bounded fix, sole writer, exact Muse Spark 1.3 Contributor /
medium, protections ON, no agents. Only this concrete boundary fixed;
prior commits, core/source/privacy/ledger/120 fixtures untouched. No
parent private files, Docker/live, keys, MMDB, real logs, provider
calls, resets, push, main, or prod changes. No full suite, browser
loop, plan, grill, or new approval — root runs the final consolidated
rerun. Live stays schema 4; migration 0008 is unreleased, so its text
grew two progress-metadata columns in place (no version churn) with an
idempotent backfill for pre-fix 0008 stores.

| Check | Result | Evidence |
| --- | --- | --- |
| Oversized restart: no decoy import (`app/db/follow.py`, migration 0008) | PASS (focused + probe) | New `tests/unit/test_parity_t5b2_follow_corrections.py::test_restart_inside_oversized_line_rejects_once_with_exact_digest`: `b'x'*1024` + one valid Combined line (limit 100); run 1 (1 poll / 1024 B) consumes 0/0 with checkpoint 1024 and prefix digest; restart (2 polls) reports 0 requests and exactly one `oversized_line` rejection, exact raw digest/offset, source bytes unchanged, marker `(1, 0)` while open and `(0, NULL)` after seal; an appended real line then inserts only itself (`/row2` at 1111) |
| Pre-marker 0008 store heals (`_ensure_follow_progress_columns`) | PASS (focused) | New `test_oversized_marker_backfills_prefixed_store`: 0008 store with both columns dropped regains them on first `run_follow`, checkpoints `(1024, 1, 0)` mid-line, and the restart still rejects exactly once with zero inserts |
| Seal/rotation tails + corrupt marker (probes, `/tmp` only) | PASS (probe) | Within-run rotation over an unfinished oversized tail drains and seals with 2 accepted / 1 `oversized_line` (gen1 `rotated` at exact digest, marker cleared); restart-rotation keeps the 300-byte checkpoint with no rewind; a hand-corrupted marker (`1, 999999`) refuses `follow:prefix_mismatch` and taints instead of adopting |
| Affected follow/migration checks | PASS (focused) | `test_parity_t5b2_follow.py` + `test_parity_t5b2_follow_corrections.py` (unit) + `test_parity_t5b2_follow_restart.py` + `test_db_migrations.py` + `test_parity_t5b3_readiness.py` + `test_parity_t5b3_helpers.py`: 48 passed |
| Ruff on changed files | PASS | `ruff check` exit 0 (`All checks passed!`), `ruff format --check` exit 0 on `app/db/follow.py` + `tests/unit/test_parity_t5b2_follow_corrections.py` |
| Full suite, browser loops, Gitleaks, image/runtime proofs | NOT RUN | Coordinator-owned (final consolidated rerun + image build); no success claimed beyond the focused evidence above |

## Documentation-only final receipts — 2026-11-02 (coordinator-observed, ACTUAL local activation)

Documentation/status only: no application, test, script, asset,
config, lockfile or schema change in this closeout. Supplied
verification record below comes from the coordinator; the implementer
invented no additional PASS. Sole writer remained Muse Spark 1.3
Contributor / medium / protections ON, no agents. Protected `main`,
`origin/main` and previous branches unchanged; no push, no `main`
merge, no public exposure, no production deployment, no provider
calls. Clean code anchor `84f440f2c593c9c32f4608e608c3530ad1cfed61`
preserved with all prior commits; canonical equivalent
`d62cb5a0929b5d2114924106dff30abfbc305fb4` on
`local/logwerk-parity-2026-11-02`. Root reconciled 33 local commits
preserving both histories; tracked trees IDENTICAL and clean. The
final `84f440f` change holds follow discard metadata plus unreleased
migration 8 / tests / docs only. Later doc-only commits repeat no
application tests; unchanged components retain the evidence below.

| Check | Result | Evidence |
| --- | --- | --- |
| Consolidated full unit/integration at clean `7f0c20d` | PASS | 1263 passed, 0 skipped, 90.60s; four upstream deprecation warnings. The initial `d753` run had stale expectations (1238 passed / 16 failed); corrected `f33` expectations/code then full rerun passed. No new full 1263 run is claimed at `84f440f`; root ran the six affected follow/migration/readiness/upgrade files: 48 passed, 0 skipped, 2.12s, plus independent same-run partial/digest, twice archive replay, stale-runner CAS + active accounting and oversized-restart counterexample probes, all PASS |
| Protected browser, initial full run | PASS with one corrected expectation | 47 passed / 1 failed in 60.26s (old Help assertion); after text-expectation correction the affected test passed in 1.66s. Other 47 unchanged-UI paths retain their result; no duplicate global browser run. Root ACTUAL `84f440f` IMAGE checks later: 24 route/theme/viewport checks (14 pages plus light/dark 1440/390 screenshots), four IP-mode transitions Full -> suffix-mask -> pseudonym-only -> Full, 599 timezone options with configured Europe/Berlin selected without query override and signed UTC offset, gated `/readyz` 200 / schema 8; zero console errors, zero external requests, zero HTTP failures, zero page horizontal overflows. Additional actual-image 12 Requests sort / API equality / detail-keyboard / filtered-htmx interactions PASS in both themes. Browser sandbox ON throughout. First root screenshot invocation had a filename TypeError; the corrected invocation completed all 24 checks — not an app failure |
| Ruff / format / lock / ambient / asset guard | PASS | Repo-wide `ruff` PASS, format 221 files PASS, `uv lock` 43 packages PASS; targeted conflicting-ambient-config 11 checks PASS (0.03s); external-asset guard PASS |
| Gitleaks (fully redacted) | PASS with two known false positives only | Full redacted public Git history at `d753` found ONLY: `b52a9fb77db80a793d774f895cefc2b9e585341a:docs/technical-spec.md:generic-api-key:787` (spec cost heading) and `016b458744e33713980b081e7c31c6c56bbe5a58:tests/integration/test_parity_t5a.py:generic-api-key:574` (fixed synthetic pytest `SESSION_SECRET` label). Incremental `d753..7f` (2 commits) and `7f..84f` (1 commit) ZERO findings. No allowlist, no history rewrite. Public tracked text + all author/committer identities: no internal authoring-tool hits; five functional ChatGPT-User catalog/rule/vector references intentionally retained, zero internal authoring-tool identity/source hits |
| Fresh-container candidate at tracked `7f` (native ARM64) | PASS | 9 passed / 0 failed: 120 rows / schema 8, 0 replay inserts, replay 0, restart persistence, protected teardown |
| FINAL fresh tracked `84f440f` native Linux ARM64 OFFLINE internal-network smoke | PASS | 24 passed / 0 failed: fresh build, API/chat-off/no-key, persistence, backup + isolated restore (0600), retention, source read-only, owned teardown. Image ID `sha256:8fcdaa34312c6379817dad359fd93318b85257c2164f57d903470083c9b22abd`, native ARM64, NOT emulated. Tag `logcarve-candidate:84f440f2c593c9c32f4608e608c3530ad1cfed61-arm64`. Native Linux x86-64 NOT RUN; amd64 emulation NOT RUN (optional, not repeated) |
| 1M benchmark (immutable git-archive `7f` source, Python 3.12.16, Darwin 27.0.0/arm64, Apple M5 Pro 18 logical CPUs / 48 GiB RAM) | PASS (observed reference timing, NO speed guarantee) | 1000000 lines -> 999000 accepted / 1000 expected rejections, 999000 inserted; replay inserts 0 / replays 999000. Slow >= 1000ms: 50000 matched. Import 25.738s / replay 20.581s; peak import 59.5 MiB / overall 103.9 MiB; DB 533610496 bytes. Query seconds: coverage 0.520, performance 15.395, slow paths 2.386, journeys 25.765, security 11.617, countries 1.437. Large windows can be slow; further tuning after acceptance. Later `84f` diff is follow/migration/docs/tests only — benchmark/parser/analytics source unchanged, so evidence reuse is verified, not assumed. Earlier 100k evidence retained; no needless duplicate 100k run. The benchmark's tiny actual-HTTP 413 probe uses a forced test cap (explicitly labelled). Root separately requested the REAL endpoint `/api/v1/exports/requests` on 999000 rows with the UNMODIFIED production 250000 cap: 413 `export_too_large`, 189 response bytes. An initial root request used the wrong route and got 404; the corrected real-route proof passed. No provider calls |
| Genuine offline DB-IP Country Lite November 2026 MMDB pipeline (independently PASS outside Contributor) | PASS | Vendor SHA-1 validated; six synthetic rows -> AU 1 / US 2 / Unknown 3 with exact errors/bytes; import -> enrich -> replay 0 keeps core IDs/HMAC/source SHA, no originals stored without key. API country/service equal, full JSON export minimized + attribution, all TEN country-filtered report pages 200 + DB-IP credit; Unknown-only selection: no false NoDB claim. Actual database remains outside Git/image/Contributor, read-only mount. Existing 120 demo documentation-range IPs all honestly Unknown; no fabricated geolocation or latency |
| ACTUAL local activation at healthy `http://127.0.0.1:8080` (completed; test readiness, NOT release approval) | PASS (activation) | Exact tested `84f440f` image `8fcda...b22abd`, non-root 10001, loopback-only, source + genuine-geodata mounts read-only, `AI_ENABLED=false` / `MODEL_API_KEY` empty. Existing named data volume retained. This normal demo bridge is NOT the isolated offline proof; that was the separate internal network above |
| Reviewed `upgrade_demo.py` executed non-root | PASS | Dry-run ORIGINAL schema 4 / 120 rows; protected online 0600 backup; migrated [5, 6, 7] then [8] and reprocessed 30 + 90 rows, each completed, no mismatch, no source change. All 120 legacy core tuples/IDs/HMAC plus full auth/token/session/ai_spend/smoke_allowance/smoke_holds hashes preserved at the migration proof point. Existing demo.env and demo-token.txt file hashes/values unchanged. Root supplied a new distinct `ORIGINAL_IP_KEY` in protected optional `original-ip.env`; no key values in docs. Capture created 120 encrypted original rows, all 12-byte nonces; external API/export still has no original addresses. Subsequent intentional admin test logins/settings transitions occur AFTER that preservation proof, so session rows are not claimed identical after testing |
| Live checks post-activation | PASS | Existing token 13 report APIs 200 (summary 120, performance timings correctly unavailable); full JSON export 120 rows and no original fixture client-IP bytes. `readyz` 200 / schema 8, session-gated. Old-rollback-image legacy analytics summary read against migrated DB returned 120 — this proves that core legacy read path, not every old feature |
| Protected backup + image-only rollback retained | PASS | Protected online DB backup retained separately outside Git; image-only rollback TAG `logcarve-demo:before-parity-84f440f2` retained. NEVER restored/reset/recreated/spliced the spent ledger or allowance. Historical real AI `02` stays INCOMPLETE 2 of 3; original 3-of-3 investigation allowance consumed. No spend permission inferred from key presence or owner coding-model choice. Product AI stays OFF pending separate future authorization; native Linux x86 NOT RUN; owner manual acceptance and video rehearsal remain OPEN |

PAR-08 (incremental follow/rotation, saved views, comparison windows)
and PAR-09 (genuine offline country lookup) are implemented, tested
and locally activated at `84f440f` — not planned, not pending. The
real MMDB pipeline ran (outside Contributor, independently PASS);
live is schema 8, not schema 4. Earlier superseded entries above
(NOT RUN / BLOCKED / pending coordinator rerun) are preserved as
history.

## Branding slice — 2026-11-02 (implementer-observed, feature branch)

Bounded owner-authorized branding change on
`feature/logwerk-parity-ready-2026-11-02` from clean `564fc8b`.
Sole writer, exact Muse Spark 1.3 Contributor / medium /
protections ON, no agents. No dependencies, settings, auth/API/DB/
model logic, schema, fixture, rule or artwork changes; social
preview PNG and README/GitHub settings untouched.

Shared inline-SVG wordmark (`Log` in `currentColor` foreground,
`Carve` in sky theme accent via external authored CSS only; text/
tspan elements reusing the bundled Inter Variable font, explicit
`viewBox 0 0 288 72` with intrinsic sizing, no embedded PNG/
base64, no script/foreignObject, no `style` attributes, no remote
URLs/fonts, no element IDs): new
`app/web/templates/partials/brand_wordmark.html`, used by both
the login hero (`app/web/templates/pages/login.html`: centred
brand block above the form, wordmark `min(280px, 72vw)`, exact
central-locale tagline below) and the authenticated header home
link (`app/web/templates/base.html`: compact `160px` /
`max-width 42vw`, same `href="/"`, accessible name `LogCarve`
via `aria-label` + screen-reader text, SVG `aria-hidden`).
`config/locales/en.json` `app.tagline` is now exactly
`Self-hosted log analytics`. Login keeps a clear `Log in`
heading and unchanged fields/autocomplete/actions/redirect/
errors/rate-limit/CSRF flow. Dark renders white/slate `Log` +
light-sky `Carve`; light renders dark/slate `Log` +
contrast-safe sky-600 `Carve`. New focused repeatable scenario
`tests/e2e/test_branding.py::test_login_and_header_wordmark`
(light 1440 + dark 390: hero/home SVG bounds, exact tagline and
home accessible name, login/navigation controls usable, no page
overflow, no console errors, same-origin requests only).

| Check | Result | Evidence |
| --- | --- | --- |
| Focused login/web integration | PASS | `test_web_hardening.py` + `test_web_overview.py` + `test_owner_ux_labels.py`: 31 passed; `test_web_corrections.py` + `test_web_oob_notice.py`: 17 passed (project `.venv`, synthetic fixtures) |
| Locale coverage after tagline edit | PASS | `test_parity_t4c_web.py` locale trio (keys cover strings, placeholders, no language chooser): 3 passed |
| Asset build + external guard | PASS | `npm run build` (vendor + js + Tailwind CSS) then `npm run check:external`: `no external references in served assets/templates`; built `app/web/static/app.css` contains the brand classes |
| Ruff on new test | PASS | `ruff check` All checks passed; `ruff format --check` already formatted |
| Server-rendered markup probe | PASS | `/login` 200: one `brand-hero`, one inline SVG, zero `<img>`, exact tagline present, old tagline absent, zero `style="`; seeded dashboard 200: one `brand-home` home link `href="/"`, `aria-label="LogCarve"`, theme/logout/nav controls intact |
| Focused branding E2E | BLOCKED | `tests/e2e/test_branding.py` (and pre-existing `tests/e2e/test_dashboard.py`, same run) cannot launch Chromium inside this shell sandbox: `bootstrap_check_in ... Permission denied (1100)` / `TargetClosedError` at browser launch, before any app code runs. Sandbox and Chromium protections left ON per instructions; no retry loop. Root runs the selected `test_branding.py` node once after freeze |
| Full 1270-test suite, Docker image build/activation | NOT RUN | Coordinator-owned (root checks actual built image); no success claimed beyond the focused evidence above |

Maps to UI-01 (central `en` tagline, exact wording), UI-02
(login + header navigation intact, same home-link behavior) and
UI-03 (theme/narrow behavior implemented; final browser
confirmation pending root run, recorded BLOCKED above, not
claimed).

## 2026-11-02 — Branding slice correction (harness + wordmark geometry)

Bounded correction on the same feature branch from clean
`9fd60d5`, same scope and protections (sole writer, exact Muse
Spark 1.3 Contributor / medium, sandbox + approval ON, no
agents, no app logic/auth/API/DB/model/settings changes, no
private parent material, no paid calls, no push/deployment, no
Chromium retry in this restricted shell, no wider suites).

Coordinator protected Chromium had inspected login/header in
both themes at 1440/390/320 (layout good, no page overflow,
login works) and reported three small corrections:

1. Harness error, not an app failure: the new E2E read SVG
   `<text>` via `Locator.inner_text`, which raises "Node is not
   an HTMLElement" on SVG text. The repaired
   `tests/e2e/test_branding.py::test_login_and_header_wordmark`
   reads SVG text via `text_content` and runs each theme/width
   case (light/dark x 1440/390/320) as an independently
   parametrized case in a fresh browser context — the old
   single-test loop reused the first login session, so the
   second `/login` visit redirected to `/` (routes.py:906).
   Each case now verifies the app-resolved `data-theme`, the
   actually loaded Inter Variable webfont
   (`document.fonts.check` + computed family), glyph ink
   bounds via `getBBox()` inside the viewBox, no page
   overflow, and a usable login form + home link. No
   protection loosened, no broad exception handling.
2. Geometry: the coordinator's loaded-Inter probe measured ink
   `x6 y~-0.46 w250.0 h65.83` in `viewBox 0 0 288 72` — the
   font bbox crossed the top by ~0.5 units with visibly more
   blank space right than left. The partial now sets
   `viewBox 0 0 282 72` with the text at `x16 y55.5`: ink
   lands at ~16..266 horizontally (even 16-unit margins, so
   the visible wordmark centers above the centered tagline)
   and ~3.0..68.9 vertically (even ~3-unit margins, fully
   inside). Wordmark design, locale tagline, responsive
   sizing, accessible home link, and no-remote/no-inline
   rules are preserved. The login hero also gains a
   screen-reader-only `app.name` alongside the `aria-hidden`
   SVG, so the visual brand has readable text.
3. History preserved: this implementer's first run recorded
   the shell-sandbox browser launch denial as BLOCKED; that
   denial remains historical environment evidence, never an
   app failure. The coordinator's protected run supplied the
   two findings above.

| Check | Result | Evidence |
| --- | --- | --- |
| `ruff check` + `ruff format --check` on repaired test | PASS | Both clean on `tests/e2e/test_branding.py` |
| Server-rendered markup probe (TestClient, no browser) | PASS | `/login` 200: one `brand-hero`, one `brand-logo` SVG with `viewBox="0 0 282 72"` (second page SVG is the log-in button icon), zero `<img>`, exact tagline present, sr-only `LogCarve` present, zero `style="`; seeded dashboard 200: one `brand-home` home link `href="/"`, `aria-label="LogCarve"` |
| Asset rebuild + `check:external` | NOT RUN | Template-only change: no authored CSS/JS/font/vendor edits, built `app/web/static/app.css` already carries the brand + `sr-only` classes, no new URLs — nothing to rebuild or re-guard |
| Repaired focused E2E + actual-image visual check | NOT RUN | Root runs `tests/e2e/test_branding.py::test_login_and_header_wordmark` (6 cases) outside this shell sandbox; no new global suite needed |

UI-01/UI-02/UI-03 mapping is unchanged; UI-03 browser
confirmation stays root-owned as before.

## 2026-11-02 — Branding slice closeout (ACTUAL root-run results)

Test/doc-only commit on the same feature branch from clean
`cb57a9f`. Application source is unchanged by this commit
(root packages `cb57a9f`); only
`tests/e2e/test_branding.py` and this log changed. Same
scope and protections (sole writer, exact Muse Spark 1.3
Contributor / medium, sandbox + approval ON, no agents, no
app/source/config changes, no private parent material, no
model calls, no full suites, no build, no push/deployment,
no Chromium from this shell).

Narrow-viewport repair: widths below 1024 click `#nav-button`,
assert `aria-expanded=true`, assert the Overview link is
visible, then close and assert `aria-expanded=false`.
Desktop asserts the visible Overview link directly. The
close uses `Escape` (the app's own overlay-dismiss path,
`assets/src/js/nav.js:37-41`) because a second click on the
menu button is intercepted by the opened side-nav overlay —
a harness interaction issue, not a product failure. All
prior assertions/protections (logo, fonts, glyph bounds,
theme, login, overflow, console-error and local-request
guards) are preserved.

| Check | Result | Evidence |
| --- | --- | --- |
| Focused branding E2E, exact 6 cases (root-run) | PASS | `tests/e2e/test_branding.py::test_login_and_header_wordmark`: 6 passed in 4.85s; 1 unrelated upstream pytest-playwright `base_url` fixture deprecation warning |
| Local Docker preview (root-run) | PASS | Fresh tracked build, image `sha256:4124314a739e27d022ea4f408b349ff15b14ce6d14792c791b21f37e1f016ffa` (`linux/arm64`), `http://127.0.0.1:8080`, user 10001, AI disabled, model key empty, 120 events, 17/17 preservation checks, 12 visual cases (1440/390/320 x light/dark), login/logout PASS, SVG glyph bounds PASS, no page overflow, no console errors, all browser requests local |
| `ruff check` on repaired test (this shell) | PASS | `UV_CACHE_DIR=/tmp/uv-cache .venv/bin/python -m ruff check tests/e2e/test_branding.py`: all checks passed |

This entry supersedes the earlier pending coordinator rows
for the repaired focused E2E and the actual-image visual
check (recorded BLOCKED/NOT RUN above). Prior failed runs
are superseded: SVG `inner_text`, session reuse, collapsed
nav role query, second click intercepted by the overlay
(corrected to `Escape`, no app change). No further checks
claimed.

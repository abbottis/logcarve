# T8 real-adapter preparation plan — reviewable, no implementation

Status: planning only, 31 Oct 2026. No application code, dependency,
credential, provider-request, push/main or deployment change made by
this document. Baseline `9aba614` (`feature/t9-dashboard` clean);
T7 fake-provider scope closed `4ecc1d3`. Execution of any real request
needs a separate owner approval after independent code review of the
implementation slice described here.

Primary docs consulted through Context7 (no secrets in queries):
`/websites/dev_meta_ai` — Responses endpoint
`https://api.meta.ai/v1/responses`, tool-calling with `function_call` /
`function_call_output` + `call_id`, stateless `store: false` (no
`previous_response_id`), usage object
`{input_tokens, output_tokens, total_tokens,
input_tokens_details.cached_tokens,
output_tokens_details.reasoning_tokens}`, Bearer `Authorization`,
Standard pricing input USD 1.25/M, output 4.25/M, cached input 0.15/M
(cached ⊂ input; reasoning ⊂ output; never double-count). Contributor
variants (`muse-spark-1.3-contributor`) stay disallowed by the gate.

## 1. Concrete binding (no invention)

- Protocol: Responses API, non-streaming POST, single documented call.
  `POST https://api.meta.ai/v1/responses`.
- Model: `muse-spark-1.3` only. Allowlist in `app/ai/gate.py`
  (`ALLOWED_PROVIDERS={"meta"}`, `ALLOWED_MODELS`, `ALLOWED_TIERS`)
  binds model/endpoint; implementation adds an endpoint allowlist
  (parsed HTTPS host `api.meta.ai`, port 443, path `/v1/responses`;
  reject credentials, query, fragment, redirects, non-allowlisted
  endpoint) without bypassing the configured runtime endpoint.
- No invented wire tier: internal `MODEL_SERVICE_TIER=standard`
  (`app/config.py`, `config/config.example.yaml`) is NOT copied to a
  wire `service_tier` value. Data mode vs scheduling tier stay distinct
  per scope; unknown/unverified fails closed before any dispatch.
- Auth: `Authorization: Bearer [REDACTED]` from protected
  `MODEL_API_KEY` only at real-run time. Tests and dry-run never read
  the product key file (`artifacts/local-demo-secrets/MODEL_API_KEY`
  stays unread, mode 0600, out of Git/build context/logs/screenshots).
- Transport policy: TLS validation on, redirects refused (any 3xx =
  provider failure, no follow), bounded connect/read/total time within
  existing `PROVIDER_TIMEOUT_S=30` (range 0.001–120), bounded response
  body (e.g. 256 KiB, exact constant in implementation), safe local
  English errors, no prompt/key/response logging (usage/status
  metadata only).

## 2. Files (bounded)

- New `app/ai/providers/meta_responses.py`: stateless Responses
  adapter (`store: false`, typed `input` items, `tools` from
  `tool_definitions()`, `max_output_tokens=2048`, explicit
  `call_id`-keyed parse). No arbitrary HTTP capability; only the
  allowlisted endpoint. Runtime holds NO hardcoded URL: the endpoint
  arrives via validated `Settings.model_endpoint` (default empty);
  the adapter parses and allowlists HTTPS host `api.meta.ai` /
  port 443 / path `/v1/responses`, rejecting userinfo/query/fragment
  and any other endpoint, and refuses redirects. Real dispatch
  revalidates endpoint/model/data-mode binding; fake-provider paths
  never require an endpoint.
- Edit `app/ai/providers/base.py`: `ProviderRequest` gains `body:
  bytes` (exact immutable serialized dispatch built, decoded-
  validated and byte-capped by the service; empty for fakes — the
  adapter sends it verbatim and never invents fields) alongside
  `prompt_text` (kept for fakes); `ToolCall` gains `call_id`;
  `ProviderResponse` gains validated `usage` dict and response `id`
  (no prompt content).
- Edit `app/ai/service.py`: replace `PRICING_VERIFIED=False` +
  `ESTIMATE_MICRO_USD_PER_1K_TOKENS`/`PROTOCOL_OVERHEAD_TOKENS`
  planning path with verified integer pricing + conservative
  reservation (Section 5); per-dispatch gate + full-payload egress
  revalidation (Section 3); `select_provider` resolves the real adapter
  only when gate + verified pricing + key present, else explicit
  unavailable. Keep all T7 regressions (worker capacity, poll deadline,
  unknown-usage-keeps-hold, trusted-scope override).
- Edit `app/config.py` + `config/config.example.yaml` (schema only, no
  credentials): `model_endpoint: str = ""` (runtime default EMPTY;
  operator supplies the allowlisted URL through validated
  config/example/settings — no hardcoded fallback URL in app
  runtime); smoke caps (`smoke_max_investigations=3`,
  `smoke_max_requests=12`, `smoke_budget_usd=1.00`); zero retries.
  No prod log paths hardcoded in adapter code.
- New `scripts/smoke_meta.py` (finite operator runner, dry-run
  default; Section 7) + persistent allowance state (DB-backed, see §7).
- New tests only (Section 8); no fixture real logs.
- UI guard: `app/web/templates/pages/ask.html` answer box +
  authored CSS in `assets/src/` (built to `app/web/static/`,
  per `app/web/AGENTS.md`): `white-space: pre-wrap`,
  `overflow-wrap: anywhere`, bounded max-height scroll. `ask.js`
  already uses `textContent` + server hrefs; keep it (no `innerHTML`).

Dependencies: zero new production dependencies (stdlib
`urllib.request`/`ssl`/`json` in the adapter). If review finds stdlib
insufficient for bounded reads, the only alternative is promoting
already-locked `httpx` to a pinned production dependency — needs
explicit approval + lockfile update. No SDK, no streaming/SSE
machinery. Retries: zero automatic retries (adequate for demo);
any retry is a new gated dispatch counted against request/cost caps.

## 3. Per-dispatch actual-payload egress (review correction applied)

The existing 8k `check_outgoing` bound cannot scan a >8k serialized
JSON body (tool schemas alone exceed it), and scanning escaped JSON
can miss escaped forbidden content. Implementation must, immediately
before EACH dispatch:

1. Revalidate live gate (`gate.validate_for_real_data`).
2. Recursively validate DECODED actual outbound values with a new
   `egress.check_wire_values` (str leaves → existing `check_outgoing`
   per-content bounds; dict/list recursion with a finite value-count
   bound; non-string scalars pass). Escaped-JSON bypass closed because
   validation sees decoded values, never the escaped serialization.
   Any violation aborts that dispatch with no retry of the same
   payload. Never inflate the existing prompt bound globally.
3. Enforce a separate documented finite total wire-byte cap
   (`MAX_WIRE_BYTES = 65536`) on the exact immutable serialized body
   (`json.dumps` with fixed separators/keys); oversize fails closed.
   Reserve cost for the exact body bytes plus a small documented
   framing constant — no separate overhead guess.
4. Replay decision (explicit): NO reasoning items, NO
   `previous_response_id`, NO raw responses or hidden state. Each
   stateless `store: false` dispatch carries only (a) the user message
   (question + scope + egress-checked evidence text, as today),
   (b) prior assistant `function_call` items the adapter itself
   produced, (c) our `function_call_output` items built from
   `serialize_evidence`-projected evidence. Never raw lines, original
   IPs, query secrets, credentials, or sensitive history; label
   minimized/truncated evidence so omitted rows are never totals.

## 4. Typed tool roundtrip / correlation (`store: false`, stateless)

- Send tools in the documented flat function format derived from
  `ToolArguments` schema; keep `store: false`, never send hidden
  `previous_response_id`.
- Replay as explicit `input` items: original `function_call` items +
  paired `function_call_output` items referencing `call_id`, in the
  same order as the calls. No server-side history.
- Validate: `output` items typed (`message` text vs `function_call`
  with `name`/`arguments` JSON string/`call_id`); `call_id` present,
  unique, 1–64 chars; `arguments` JSON parses to a dict passing
  `ToolArguments` (`extra="forbid"`); unknown tool name, unknown
  `call_id` in an output item, duplicate `call_id`, or out-of-order
  output items fail closed (no execution, hold kept per §6).
- Models never control actor scope, site/source/time, URLs, paths, SQL
  or executable tools: `_execute_bounded_tool` keeps overriding
  `site_id`/`source_id`/`time_from`/`time_to` from `ValidatedScope`.
- Evidence filters (`_evidence_filters` + `app/web/evidence.py`)
  already carry matchers/paging/bucket; replay tests must assert every
  outbound field round-trips (Section 8).

## 5. Verified integer pricing / usage / reservations

Replace fake `ESTIMATE_MICRO_USD_PER_1K_TOKENS` with versioned
constants, e.g. `PRICE_INPUT_MICRO_PER_M=1_250_000`,
`PRICE_OUTPUT_MICRO_PER_M=4_250_000`,
`PRICE_CACHED_MICRO_PER_M=150_000`, `PRICING_VERSION="2026-10-31-dev.meta.ai"`,
`PRICING_VERIFIED=True` only in the real path.

- Reservation per dispatch (before send): full serialized input size
  via `estimate_input_tokens_upper` (byte-length upper bound + schema
  framing, no cache assumption) at input rate + `MAX_OUTPUT_TOKENS`
  at output rate, integer micro-USD ceiling.
- Charge after response: `(input_tokens - cached_tokens) * input_rate
  + cached_tokens * cached_rate + output_tokens * output_rate`,
  rounded up to whole micro-USD, minimum 1 micro-USD for a dispatch.
- Validate usage: all three integers ≥ 0; `cached_tokens ≤
  input_tokens`; `reasoning_tokens ≤ output_tokens` (informational,
  still billed at output rate); `total_tokens` consistent when
  present. Malformed/absent usage, or timeout/cancel/error after
  dispatch (unknown size), keeps the FULL reservation hold —
  conservative, never released as free. Tighter existing
  daily/stop/total caps bind alongside the smoke caps.

## 6. Timeout / cancellation

Reuse `_wait_provider` (daemon worker, `WORKER_CAPACITY=8`,
`WORKER_POLL_S=0.02`, hard deadline `timeout_s`, `cancel` event).
Adapter `complete()` must: use bounded socket timeouts, check
`cancel` before connect/send/read, abort promptly, never swallow
`ProviderCancelled`. 504/timeout/connection errors map to
`provider_unavailable` with deterministic API/dashboard intact
(AI-04); the step hold is kept as unknown charge. No streaming (avoids
SSE/timeout complexity); a 504 advises smaller work, not a blind
retry — with zero retries the run surfaces it and stops.

## 7. Persistent finite smoke allowance + dry-run runner

Standing proposal (unchanged): ≤ 3 synthetic investigations, ≤ 12
provider requests including failed attempts/retries, ≤ USD 1.00
estimated product cost; tighter existing limits bind. These are
ceilings, not targets; stop BEFORE a cap, never after overspending.

- State (review correction): LIFETIME counters for this single owner
  approval — never reset at UTC midnight, never auto-renewed (normal
  daily `ai_spend` accounting still rolls UTC separately). Versioned
  schema `smoke_allowance` (`version=1`, single row: caps snapshot +
  used investigations/requests/micro-USD + active holds). First use
  records the caps; later runs with LOOSER caps are refused (no silent
  widening). Atomic admission/reservation per request (failed attempts
  and in-flight work count) shared across concurrent runners and
  restarts via the writer transaction; conservative cost holds.
- Runner `scripts/smoke_meta.py`: defaults to `--dry-run` (builds the
  three investigations, runs the full pipeline against a mock
  transport, asserts hand-derived expectations, touches no key/network).
  Real run requires BOTH `--real-run` and an explicit env pointing at
  the protected key file; otherwise refuse. Pre-dispatch: check
  persisted allowance; refuse when the next conservative reservation
  would exceed any cap. Every attempted request (incl. failures)
  decrements/accrues immediately. Prints only safe metadata
  (model/endpoint/usage/duration/tool counts/cost); never prompts,
  keys, or raw evidence.
- Dry-run must pass in review/CI without the key; real run needs the
  separately-approved owner go-ahead after independent review.
- Safe durable usage metadata: per-request ledger (JSONL outside
  version control) with model, endpoint, input/output/cached/
  reasoning counts, duration, tool counts, status and micro-USD cost
  only — never prompts, responses, or evidence content. Reasoning is a
  subset of billed output, cached a subset of input. Unknown/malformed
  dispatch usage retains the full hold. Zero automatic retries.

## 8. Tests (mock HTTP only; no key, no network)

Unit/integration with injected fake/mock transport at the HTTP
boundary (record exact outbound JSON + assert):

1. Tool roundtrip/call correlation: multi-call response, paired
   outputs, duplicate/unknown `call_id`, malformed `arguments` JSON.
2. Binding: model/endpoint/tier pinned; redirect followed-refused;
   TLS validation on; unknown endpoint rejected; Contributor/unknown
   tier blocked mid-session and on replay.
3. Outbound-field completeness: every wire field asserted incl.
   replayed `function_call_output` items; hostile tool content
   (prompt-shaped UA/Referer/path, secret-shaped strings) never
   serialized past the gate.
4. Bounds: body cap, `max_output_tokens` cap, oversized/malformed
   response rejected; `cached_tokens > input_tokens`,
   `reasoning > output`, negative/absent usage → keep full hold.
5. Concurrency/caps: simultaneous reservations serialize; request,
   investigation and cost cap races stop-before-overspend; restart
   keeps allowance; missing key + provider failure leave
   deterministic API/dashboard usable.
6. Filter-replay edge cases (exact, Section 9) and UI guard case
   (Section 10) as repeatable tests.

Commands at implementation: `uv run --locked pytest tests/unit
tests/integration`, `uv run --locked ruff check .`,
`ruff format --check .`, `uv lock --check`, redacted Gitleaks of
candidate + history. Protected browser E2E (14) + populated visual
matrix rerun by coordinator (Chromium/Docker retry stays coordinator
side; do not retry known-blocked Chromium/Docker in Muse).

## 9. Exact filter-replay edge cases (from T9-B carry)

Current mismatch: web `_parse_matchers` uppercases `method`,
lowercases `referer_host`, requires `/`-prefixed `path_prefix`,
while `ToolArguments`/`AnalyticsFilter` accept broader exact strings
and `queries.py` compares `method = ?` / `referer_host = ?` /
`path LIKE prefix%` exactly. Resolution (no weakened SQL, no invented
filesystem semantics):

- Treat tool/web filter values as exact analytics matchers: NO
  case-folding inside the tool layer. `GET` ≠ `get`; `OPTIONS` with
  `path_prefix="*"`... note `*` is not `/`-prefixed so the web bar
  rejects it — the tool may still carry `method="OPTIONS"` with no
  path matcher for `OPTIONS *` rows; the evidence URL then omits
  `path_prefix` and reproduces the same read (test both).
- Resolution (review correction): these are SQL string matchers, not
  filesystem paths — PRESERVE exact valid values end to end, never
  omit a requested matcher. Tool layer stays exact (no folding).
  Web `_parse_matchers` stops folding case (method kept verbatim,
  referrer kept verbatim) and additionally accepts the literal
  `path_prefix="*"` (the `OPTIONS *` target the parser stores
  verbatim; LIKE-escaped, so `*` is data, never a glob) alongside
  `/`-prefixed values; `noslash` and other non-conforming values
  still 400. Evidence URLs already carry exact values.
- Cases to lock (all replayed tool→evidence-URL→web identically,
  including zero-result reads, plus source/window/paging): `GET` vs
  lowercase `get` (exact; `get` asserts zero, not fallback); `OPTIONS`
  with `path_prefix="*"` (1 row) vs absent prefix vs `/`; mixed-case
  referrer `Example.ORG` preserved verbatim (zero rows; import stores
  lowercase); overlong/non-ASCII matchers still fail closed.
- Keep shared bounds and parameterized SQL (`queries.py` `?`
  placeholders, LIKE-escape).

## 10. Long / multiline plain-output UI guard

Current `ask.html` answer box: `prose ... text-sm` with normal
whitespace and no wrap override; `ask.js` sets `textContent` (safe).
Add: `whitespace-pre-wrap`, `break-words`/`overflow-wrap:anywhere`,
`max-h` + `overflow-auto` on the answer container. Tests: synthetic
browser success response with (a) a 2 000-char single token,
(b) multiline text with blank lines, (c) HTML-shaped text
(`<img src=x onerror=...>` as TEXT) — assert no markup execution, no
360 px overflow, preserved line breaks, server evidence hrefs intact,
all T9 regressions kept.

## 11. Three hand-derived fixture cases (review correction applied)

ONE combined synthetic fixture (`tests/fixtures/combined/t8_smoke.txt`,
no real logs) with three separate explicit UTC case windows.
Implementation writes the fixture; these numbers are the check targets:

- A — AI crawlers: 12 rows = 7 `GPTBot/1.0` + 2 `ClaudeBot/1.0` + 3
  plain browsers. Ask claimed-family activity with limits; do NOT
  attribute 404s to an agent without correlated tool data. Expect
  `get_crawler_claims` = 2 families (`bot-ai-gpt` requests=7,
  `bot-ai-claude` requests=2), claimed-only wording.
- B — 404s with referrers: 10 rows, 5 x 404 on `/docs/missing-page`
  with `referer_host=blog.example.org` (3) / `docs.example.org` (2).
  Expect top-404 path `/docs/missing-page`=5, top referrer
  `blog.example.org`=3, evidence link replays status=404 +
  path_prefix + referer_host exactly.
- C — suspicious paths: 8 rows incl. `/.env` 404 + `/.git/config` 200
  (sensitive-path group, 2 requests) + 4 other 404s from the same
  first client (5 errors total, repeated-client finding) +
  `/admin?token=synthetic` 200 (query discarded at import) +
  `OPTIONS *` 200. Expect EXACTLY 2 `get_security_findings`
  (sensitive-path requests=2; repeated-client errors=5). `OPTIONS`
  exact-method replay returns 1 row while lowercase `options`
  returns 0.

## 12. Remaining risks / NOT RUN

AI-01/02 stay NOT RUN until authorized execution. Effective Standard
handling, credited balance and model access were owner-verified outside
the transcript — not re-proven here. App caps do not bound other
keys, parallel/in-flight usage or delayed billing. Linux x86-64,
container/offline persistence and final delivery gates outstanding.
Chromium/Docker blocked in Muse stay coordinator-side.

## 13. Independent-review rework R1–R7 (014e4e2, implemented)

- R1: wire tools converted at one boundary to
  `{type: "function", name, description, parameters}`
  (`response_tool_definitions()`); legacy `arguments` key never sent.
- R2: TLS context attached via `HTTPSHandler(context=...)`
  (`_default_opener`); `OpenerDirector.open` called with real
  `(request, timeout)` signature only. Stub-opener tests cover the
  native wrapper (TLS creation, redirect refusal, body/response
  bounds, timeout mapping). Absolute wall-clock bound stays with the
  outer worker/control deadline; socket timeout bounds each read only.
- R3: known bounded `reasoning` items accepted and ignored (never
  forwarded/logged); unknown items fail closed. Response `status`
  must be `completed`, `model` must equal the configured allowlisted
  model, `total_tokens` must equal input+output; reasoning ⊂ output,
  cached ⊂ input. Mocks mirror the full documented shape.
- R4: `build_dispatch_body` egress-validates DECODED values
  (instructions, user text, per-call arguments, evidence, tool
  schemas) BEFORE JSON-encoding; embedded `arguments`/`output` JSON
  is never rescanned as the gate.
- R5: `init_or_check` persists the minimum caps atomically;
  narrowing binds immediately, widening refused, spend never refunded.
- R6: `smoke_enforced=None` enforces the shared lifetime allowance on
  every REAL invocation (UI/API chat included); fake-only paths stay
  off unless explicitly enabled. `real_run` honors operator verified
  config (never forces it), preflights seed-or-verify of the exact
  30-row fixture with aggregates, and the entry is tested offline
  with a temporary fake key plus stub transport.
- R7: real runs preserve sanitized application results (plain answer,
  model/tool/evidence IDs, filters/window/coverage/usage, status) and
  failure ledger entries under ignored `data/`; cases succeed only
  with actual tools and evidence.
- Binding: `validate_body`/`check_dispatch` enforce model/stateless
  binding pre-admission (service) and pre-send (adapter); crafted
  Contributor bodies never reach transport or key headers.

## 14. Reinspection safety rework (a0a022a, implemented)

- Staging: exclusive `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 fixture creation,
  or byte-exact read-only reuse; symlinks, non-regular files, and
  foreign content refused. Existing sentinels/symlink targets never
  truncated, moved, deleted, followed, or chmodded.
- Provenance: existing stores recognized read-only before any
  migration/seed/key load — exact committed fixture SHA256 in every
  import fingerprint, completed/unflagged imports, single site/source,
  no foreign rows — plus the hand-derived aggregates. Counts alone
  never establish provenance.
- Outputs: ledger/results exclusively claimed 0600 and validated
  before any dispatch; symlinks, key/source/DB collisions, and
  pre-existing files refused, preserving actual allowance and ledgers.
  No chmod of anything, ever.

## 15. Final preparation details (implemented)

- Fixed product profile `reasoning: {"effort": "low"}` on every real
  dispatch (per official `/docs/features/responses`; `low`
  supported, default not fixed). `max_output_tokens` 2048 and all
  caps unchanged; reasoning bills inside output, covered by the
  existing MAX_OUTPUT reservation. Binding rejects other efforts.
  Coding-session effort unaffected.
- Validated bounded provider `response_id` (1–128 chars) and
  `call_id` (1–64, unique) preserved in result, usage, ledger, and
  application artifacts alongside local investigation/tool/evidence
  IDs; no raw response/reasoning/prompt retention.
- Minimized real wire: user text is question + trusted scope only;
  each tool result replays exactly once via typed exchanges
  (fake-provider history behavior preserved, no bound increases).
  Captured-body test asserts the single replay with call_id
  correlation on the resulting exact bytes.

# AI providers

LogCarve ships an optional server-side assistant for log investigations.
It is strictly opt-in: the dashboard, the external API and the
deterministic analytics work fully with chat disabled, no model key and
no Internet. Exactly one provider/model is active at a time — LogCarve
is not a general-purpose model proxy.

## Supported providers

Read from `app/ai/catalog.py` (ADR 0004). Each provider has one
vetted model, one exact trusted native HTTPS endpoint (no configurable
URL surface; keys travel in auth headers, never in URLs) and verified
per-model pricing with provenance.

| Provider | Model | Native endpoint | Tier | Live verification |
|---|---|---|---|---|
| Meta | `muse-spark-1.3` | `https://api.meta.ai:443/v1/responses` | Standard | Owner-authorized synthetic run PASS (see [verification](verification.md)) |
| OpenAI | `gpt-6-luna` | `https://api.openai.com:443/v1/responses` | Standard | NOT RUN (native offline tests PASS; no owner key or call) |
| Google Gemini | `gemini-3.5-flash-lite` | `https://generativelanguage.googleapis.com:443/v1beta/models/gemini-3.5-flash-lite:generateContent` | Paid API | NOT RUN (native offline tests PASS; no owner key or call) |
| Anthropic Claude | `claude-haiku-5-5` | `https://api.anthropic.com:443/v1/messages` | API | NOT RUN (native offline tests PASS; no owner key or call) |

Tiers are labeled honestly: Gemini Paid/API and Anthropic API are
never presented as Meta Standard. Pricing provenance per model:
Meta 2026-10-31 (`dev.meta.ai`), OpenAI/Gemini/Anthropic 2026-11-02
(`developers.openai.com`, `ai.google.dev`, `platform.claude.com`).
Integer micro-USD arithmetic lives in each adapter. OpenAI and
Gemini cached-input counts are a subset of input and are never added
on top of the input total. Anthropic counts differ: base input,
cache-creation and cache-read tokens are disjoint components that
are summed once into the billed input total, never double-counted
and never dropped.

Native wire profiles (enforced before any send):

- OpenAI Responses carries only flat direct function tools with an
  explicit `strict: false` on each tool — the deliberate non-strict
  opt-out. Omitting `strict` would let the API attempt strict schema
  normalization first, so omission and `strict: true` both fail the
  dispatch check. The flag is set on per-dispatch copies; the shared
  tool schemas used by the other providers are never modified.
- Gemini `generateContent` requires the unique server-provided
  `FunctionCall.id` with every function call (Gemini 3 always sends
  one). A missing, null, empty or invalid id fails the run closed —
  no positional substitute is ever invented — and the matching
  `FunctionResponse.id` echoes the exact provided id. The opaque
  `thoughtSignature` is preserved as a sibling part in order and is
  never reconstructed.
- OpenAI Responses requests carry explicit `service_tier: "default"`
  for standard pricing/performance: omitting the field would inherit
  the Project's configured tier, so a missing or non-default tier
  fails dispatch. A response that explicitly reports a non-default
  tier fails closed instead of being accounted at standard rates.
- Anthropic Messages requests carry explicit
  `service_tier: "standard_only"` for standard-capacity processing:
  the documented `"auto"` default would use Priority capacity when
  available, so omission fails dispatch. A usage report with an
  explicit non-standard tier fails closed instead of being accounted
  at standard rates.
- Gemini requests carry no processing-tier field: omission means
  Standard under the `generateContent` priority/flex inference
  documentation, so the adapter leaves the field unset.

Processing-tier flags describe the request LogCarve sends; they do
not prove how the provider actually processed a call or which
privacy mode applied. Response-tier checks above are accounting
guards, not provider handling proofs. Official tier references:
[OpenAI service tiers](https://developers.openai.com/api/docs/guides/service-tiers),
[Anthropic service tiers](https://platform.claude.com/docs/en/api/service-tiers),
[Gemini priority inference](https://ai.google.dev/gemini-api/docs/generate-content/priority-inference),
[Gemini flex inference](https://ai.google.dev/gemini-api/docs/generate-content/flex-inference).

Primary API references used for the native transports:

- OpenAI function calling, Responses migration and Responses reference:
  [function-calling](https://developers.openai.com/api/docs/guides/function-calling),
  [migrate-to-responses](https://developers.openai.com/api/docs/guides/migrate-to-responses),
  [responses-cancel](https://developers.openai.com/api/reference/resources/responses/methods/cancel)
- Gemini thought signatures, function calling and Gemini 3.5 notes:
  [thought-signatures](https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures),
  [function-calling](https://ai.google.dev/gemini-api/docs/generate-content/function-calling),
  [whats-new-gemini-3.5](https://ai.google.dev/gemini-api/docs/generate-content/whats-new-3.5)
- Anthropic API overview and Messages:
  [overview](https://platform.claude.com/docs/en/api/overview),
  [messages](https://platform.claude.com/docs/en/api/http/messages)

## Setup

All provider configuration lives in the backend Settings page (local
admin session + CSRF).

1. Generate a dedicated `AI_SETTINGS_KEY` (32 random bytes, base64 or
   hex) and preserve it separately from every other secret. Stored
   provider keys are AES-256-GCM ciphertext bound to their provider.
   Without this key only the saved provider keys become unreadable
   (dispatches fail closed); analytics and data backups still restore
   normally. See [backup and restore](backup-restore.md) for the key's
   persistence/backup role.
2. In Settings, select the provider and its vetted model and enable
   the assistant. Entering a key alone does not activate anything;
   Save settings once all steps below are complete.
3. Enter each provider key in Settings, or mount per-provider env
   fallbacks (`MODEL_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
   `ANTHROPIC_API_KEY`). Blank keeps the stored key, explicit remove
   deletes it; removal while an env fallback exists reports
   env-managed.
4. Acknowledge the data policy per provider (real-data or
   synthetic-only demo mode). Synthetic mode additionally requires
   the operator `AI_SYNTHETIC_SOURCE` assertion. Acknowledgments never
   transfer between providers.
5. Anthropic only: a workspace ID is REQUIRED alongside a
   non-workspace-scoped key (sent as the bounded
   `anthropic-workspace-id` header); it is optional only for an
   already workspace-scoped key, which needs none.
6. Create the explicit bounded runtime usage grant before any paid
   call (initially there is no grant — fail-closed):

   ```bash
   python -m app.db.cli --db /data/logcarve.sqlite3 \
     ai-allowance-grant --investigations 3 --requests 12 --usd 1
   ```

   Enabling AI never creates a grant, and settings saves/restarts
   never reset it. The historical T8 smoke ledger is preserved
   untouched alongside it. App limits do not cap other keys,
   parallel usage, or delayed billing — they bound this product
   installation only.

## Boundaries that always hold

- Unknown providers, models, tiers, or endpoints fail closed before
  any data moves; mid-investigation provider/model/key/policy changes
  fail the run rather than replaying earlier history elsewhere.
- Only needed aggregates and sanitized evidence reach the provider:
  raw log lines, original IPs, query values and secrets never leave
  the installation. Original client IPs never reach the external API,
  exports, errors, model tools, or version control.
- The assistant gets bounded, typed read-only analytics tools only
  (no arbitrary HTTP, files, shell, SQL, or configuration edits), with
  site/time limits, output limits, timeouts, step limits and budget
  checks on the server.
- Every finding reports evidence IDs, filters, observation time,
  coverage and limitations. Security patterns are investigation
  candidates, never confirmed attacks. Model failure leaves
  deterministic analytics and the API online.
- User-Agent matches are claimed bots, not verified identities. No
  visits, visitors, sessions, conversions, rankings, or training-use
  claims are derived from access logs.

## Troubleshooting

The chat surface shows a plain English unavailable message; the codes
below are what the service records (see `app/ai/service.py`).

| Symptom | Recorded code | Likely cause |
|---|---|---|
| Assistant unavailable before any provider contact | `usage_not_authorized` | No runtime usage grant yet; create the bounded grant above |
| Assistant unavailable before any provider contact | `egress_blocked` | Policy/acknowledgment missing (e.g. real-data policy not acknowledged, synthetic source not asserted, unknown provider/tier) |
| Assistant unavailable after dispatch | `provider_unavailable` | Refused/auth/rate-limit/server reply, timeout, malformed or oversized answer, or a non-standard reported processing tier; never retried automatically — check key, endpoint reachability and policy, then retry manually only while budget and the runtime usage grant still cover it (every retry spends allowance) |
| Investigation stopped with a bound message | `output_limit_reached` | Prompt, history, evidence, or answer bound exceeded; narrow the window or reduce output |
| Settings-backed dispatch refused | `ai_unavailable` (HTTP 503) | AI settings store missing, corrupt, or unreadable: `ai_store_error` is the internal settings attribute (not a returned code), mapped by the chat route from `BackendUnavailable` before dispatch to 503 `ai_unavailable`; dispatch fails closed while analytics stay online |
| Analytics store unreadable during scoping | `store_unavailable` (HTTP 503) | The genuine local `InvestigationError` code for an unreadable analytics data store during scope validation — emitted by the API handler, distinct from the settings-store attribute above |
| Answer cannot be shown | (evidence filter) | Provider answer failed the safe-text check; deterministic pages are unaffected |

Other-provider account live checks are NOT RUN in this repository:
live verification requires owner keys and explicit per-call
authorization, which only the Meta Standard synthetic run has
received. See [deployment](deployment.md) for host operation,
[privacy and data egress](privacy-and-security.md) for the full
boundary, and [ADR 0004](decisions/0004-multi-provider-ai.md) for the
accepted scope.

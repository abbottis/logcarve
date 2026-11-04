# ADR 0004 — Multi-provider AI assistants with backend settings

- Date: 2026-11-02
- Status: **Accepted** 2026-11-02 by owner (task "Authorized AI-provider settings extension").
  The owner's current message explicitly extends the previous Meta-only
  product scope to OpenAI, Google Gemini and Anthropic Claude alternatives,
  configurable in backend Settings, with keys provided later by the owner
  and AI to be enabled in the local demo. No paid/live usage budget is
  renewed by this selection.
- Scope: native server-side adapters for Meta (preserved), OpenAI
  Responses, Gemini `generateContent`, Claude Messages; a small
  vetted model catalog (Meta `muse-spark-1.3`, OpenAI `gpt-6-luna`,
  Gemini `gemini-3.5-flash-lite`, Claude `claude-haiku-5-5` — the Claude
  ID confirmed 2026-11-02 against the official Anthropic Python SDK
  `ModelParam` literal via Context7); DB-backed backend AI settings with
  per-provider AES-GCM encrypted keys under a new dedicated
  `AI_SETTINGS_KEY`; a separate explicit bounded runtime usage
  authorization (initially no grant, fail-closed).

## Accepted exceptions (bounded to this slice)

1. The Meta-only product-model scope is extended to the three listed
   providers/models, each with verified model-specific pricing and its
   exact trusted native HTTPS endpoint (no arbitrary endpoint URLs).
2. Local authenticated admin may store per-provider keys (DB ciphertext
   or operator env fallback) and select synthetic-only demo mode or
   acknowledge a provider-specific real-data policy per provider.
   Acknowledgments never transfer across providers.
3. Gemini Paid/API and Anthropic API tiers are labeled as such and never
   as Meta Standard; Google free/unknown/unverified real-data handling
   stays blocked.

## Invariants preserved

Shared deterministic analytics, independent external API operation with
AI off, egress minimization, tool allowlist, per-step budget
reservation, the historical once-only T8 smoke ledger (never
reset/cleared/expanded implicitly), key separation, CSRF/admin-session
protection on mutations, analytics-token exclusion from settings/chat,
and all PAR-01–PAR-10 demo protections. Enabling UI alone spends
nothing and creates no allowance. Old nonzero daily-limit semantics are
unchanged; limits are global across providers.

## Acceptance impact

New criteria `AI-05` (native multi-provider transports), `AI-06`
(backend AI settings), `AI-07` (runtime usage authorization); extends
AI-01–AI-04, PRIV-01–02, COST-01–02, UI-02–03, AUTH-01–02, API-04,
OPS-02. Recorded evidence in `docs/verification.md`.

## Update 2026-11-02 — Alternative model upgrade (owner-authorized)

Owner request 2026-11-02 (task `artifacts/model-upgrade-2026-11-02/task.md`):
replace the three alternative defaults with exact `gpt-6.1-terra`,
`gemini-3.8-flash`, `claude-sonnet-5-5`; Meta `muse-spark-1.3` unchanged
and still the selected demo provider. Authorizes directly required
native wire/pricing compatibility updates only (no arbitrary models or
URLs). Affected criteria: AI-05/AI-07, COST-01/02, PRIV-01/02.

- OpenAI: `reasoning.effort none` retained, `strict: false`,
  `store: false`, `service_tier: default`; input includes cached and
  cache-write subsets (write retention unreported → conservative 12h
  rate; worst-case write reservation). No explicit caching features.
- Gemini: fixed cheap thinking `LOW`; paid intro rates through
  2026-12-31, higher standard rates from 2027-01-01 (reverify); native
  `FunctionCall.id` + sibling `thoughtSignature` replay preserved.
- Sonnet: `thinking: {"type": "between_tools"}` with fixed
  `output_config: {"effort": "low"}`; flat pricing (no 100k tier);
  disjoint input/cache-write/cache-read accounting; exact original
  assistant-block replay (text/thinking/tool_use order, verbatim
  original inputs) bound to same provider/model with unchanged
  system/tools/prefix; opaque thinking excluded from
  answer/UI/DB/log/evidence. Minimal metadata extension:
  `anthropic_assistant_content` allowlisted in service validation.
- Live runs use owner-supplied keys with real runs pending coordinator;
  prior "no owner key" wording is superseded. Historical model choices
  above are preserved as history.

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

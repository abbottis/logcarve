# Decision register

An ADR is proposed until an owner explicitly accepts it. Record date, owner decision/reference, rationale and acceptance-criteria impact. Documentation scaffolding does not accept the application design.

| Decision | Proposed direction | Status |
| --- | --- | --- |
| [0001 — MVP architecture](0001-mvp-architecture.md) | Single-site Combined, SQLite, FastAPI and server-rendered local-assets UI | Proposed historical record; implemented direction documented in `docs/architecture.md` and `docs/verification.md` (no acceptance invented) |
| [0002 — MVP scope settlement](0002-mvp-scope-grill.md) | License, deployment target, verified-then-capped smoke, separate-clone integration, 30-day retention, derived-on-read findings | Accepted 2026-10-29 by owner (decisions 1–6); later stages need their own authorization |
| [Development tool workflow](../development-tools.md) | `uv`, Git/`gh`, pytest, Ruff, Playwright and Gitleaks; Context7/Chrome baseline and optional GitHub MCP | Documented on 2026-10-28 at owner's request; dependency versions/bootstrap remain pending |
| Auth and API credentials | Local admin session plus separately scoped Bearer tokens | Proposed |
| Privacy/IP | Secret HMAC pseudonymization; no routine raw data/queries | Accepted direction (ADR 0002/0003); implemented with the bounded local-admin original-IP exception per ADR 0003 |
| Finding storage | Derive on read initially unless persistence is needed | Accepted (ADR 0002, decision 6); implemented shared deterministic layer |
| Deployment host | Private synthetic Linux/Compose demo first; Plesk later | Open |
| Frontend dependencies | Tailwind 4, daisyUI 5, htmx, Chart.js 4 | Proposed; exact versions not locked |
| Runtime model | `muse-spark-1.3` Standard with verified account/provider policy | Required direction; access/effective tier unverified |
| Open weights | `meta-models/muse-spark-open-1026` on a separately verified provider | Optional; URL/access/credits unknown |
| External access | Local/VPN or explicitly secured TLS reverse proxy | Open; no automatic public exposure |
| Project license / LogWerk reuse | Select license and document each imported source | Apache-2.0 decided 2026-10-29; 70 MIT bot patterns adapted 2026-11-01; see `THIRD_PARTY_NOTICES.md` |
| [0003 — LogWerk parity](0003-logwerk-parity.md) | Bounded parity scope with local-admin IP/masking, journeys, enrichment, offline GeoIP | Accepted 2026-11-01 by owner; T1–T5 implemented and locally activated (see `docs/verification.md` final receipts) |
| [0004 — Multi-provider AI](0004-multi-provider-ai.md) | Native Meta/OpenAI/Gemini/Claude transports, backend settings with encrypted keys, explicit runtime usage grant | Accepted 2026-11-02 by owner (plus model-upgrade update); implemented per `docs/ai-providers.md` and `docs/verification.md` |
| Meta credits/account | Verify actual team credit and billing/data-mode settings | Unverified; no balance assumed |
| Public end users / submission | Review current terms, regions and Official Rules when relevant | Pending before public release/submission |

Use `NNNN-short-title.md` for subsequent ADRs. Keep decisions here rather than adding conflicting instructions or silently editing the source snapshot.

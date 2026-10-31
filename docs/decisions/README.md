# Decision register

An ADR is proposed until an owner explicitly accepts it. Record date, owner decision/reference, rationale and acceptance-criteria impact. Documentation scaffolding does not accept the application design.

| Decision | Proposed direction | Status |
| --- | --- | --- |
| [0001 — MVP architecture](0001-mvp-architecture.md) | Single-site Combined, SQLite, FastAPI and server-rendered local-assets UI | Proposed |
| [Development tool workflow](../development-tools.md) | `uv`, Git/`gh`, pytest, Ruff, Playwright and Gitleaks; Context7/Chrome baseline and optional GitHub MCP | Documented on 2026-10-28 at owner's request; dependency versions/bootstrap remain pending |
| Auth and API credentials | Local admin session plus separately scoped Bearer tokens | Proposed |
| Privacy/IP | Secret HMAC pseudonymization; no routine raw data/queries | Spec requirement; implementation details pending |
| Finding storage | Derive on read initially unless persistence is needed | Proposed |
| Deployment host | Private synthetic Linux/Compose demo first; Plesk later | Open |
| Frontend dependencies | Tailwind 4, daisyUI 5, htmx, Chart.js 4 | Proposed; exact versions not locked |
| Runtime model | `muse-spark-1.3` Standard with verified account/provider policy | Required direction; access/effective tier unverified |
| Open weights | `meta-models/muse-spark-open-1026` on a separately verified provider | Optional; URL/access/credits unknown |
| External access | Local/VPN or explicitly secured TLS reverse proxy | Open; no automatic public exposure |
| Project license / LogWerk reuse | Select license and document each imported source | Open; nothing imported |
| Meta credits/account | Verify actual team credit and billing/data-mode settings | Unverified; no balance assumed |
| Public end users / submission | Review current terms, regions and Official Rules when relevant | Pending before public release/submission |

Use `NNNN-short-title.md` for subsequent ADRs. Keep decisions here rather than adding conflicting instructions or silently editing the source snapshot.

# Changelog

## Unreleased

### 2026-10-31 — T9-B reinspection residuals (feature/t9-dashboard)

- Fixed populated Security narrow overflow: the client pseudonym wraps safely (`break-all`) under a localized "Client pseudonym" label; 360px fits in both themes.
- Fixed `_page_url` query building with one shared canonical query builder (no string stripping of the route path); prev/next URLs parse to exact filter keys.
- The active navigation link keeps the full current canonical filters after reload; other views keep the shared window state.
- Negative Ask browser tests match exactly one native failed-resource console entry for the deliberate 409/503 with structured source metadata; unrelated errors still fail.

### 2026-10-31 — T9-B independent-review corrections (feature/t9-dashboard)

- Fixed the Security crash on populated findings (immutable `Finding` dataclasses now render through plain view dicts) and enriched finding/crawler cards with meaning, request/error counts, inline evidence samples, window, coverage, filters and limitations; support links point at the page that actually lists the rows, never labelled complete evidence.
- Ask Send now posts through the shared `LogcarveCSRF.postJson` helper with bounded 403 recovery; chat evidence carries server-generated per-result hrefs from the single trusted formatter (`app/web/evidence.py`), and the browser renders them directly with no route map or URL builder shipped.
- Canonical URLs and HX-Push-Url targets now match each full-page route, so Errors/Security/Crawlers reload and history stay on the page; malformed query values (`status=²`, over-long hosts) return safe 400s via shared contract bounds plus a guarded filter build.
- Sample and truncation labelling throughout: agent/path evidence records shown/total counts, crawler paths note the first-50 agent cap, and the scan bounds are explicit in cards.
- Extended integration tests (populated both-rule findings, malformed 400s, per-route canonicals, href replay against actual tool result counts, >50 agents) and real-interaction browser tests (Ask success/failure/disabled with POST scope capture, Ask Apply scope flow, structured two-error console matching for the rejected window).

### 2026-10-31 — T9-B remaining views (feature/t9-dashboard)

- Added Security, Crawlers, Errors, Ask AI, Settings/API Access and Data Sources views over the shared analytics layer, with canonical filters, bounded server pagination, reproducible evidence links and read-only settings/source guidance (no upload or path input, CLI-based token administration unchanged).
- Ask AI reuses session/CSRF against the existing chat endpoint with honest disabled/unavailable states; starter questions populate only, answers render as escaped plain text, and evidence links rebuild from the server-generated tool→page contract plus the returned envelope (site, source, window, matchers, paging, bucket, tool call ID, observation time).
- The filter bar resubmits matchers, source, page size and bucket on Apply (offset resets deliberately); overview tables honor requested limit/offset with honest position notes; side-nav links adopt the newly applied shared window on every data page; failed Applies show a visible alert and keep the previous valid results.
- Extended integration tests (envelope contract, source mapping, scope preservation, paging honesty, failure wiring) and real-interaction browser tests (Ask starters/disabled send, Apply scope/nav sync, reversed-window alert, paging notes).

### 2026-10-31 — T9-A residual corrections (feature/t9-dashboard)

- Constrained intrinsic card/grid/stat/canvas widths (min-width:0 chain, bounded table scrollers, canvas bound, debounced chart re-render on resize) without clipping the page; the observation window now refreshes with partial updates.
- Fixed e2e filter flow to await the real partial response and assert displayed window plus changed data; fixed color assertions with OKLCH-aware comparison, tolerance and contrast checks.
- Corrected the narrow-window KPI expectation to the hand-derived 8 events (missing-page 09:15:32Z and the 07:14Z 500 excluded) and paired light-theme sky-600 with a slate-950 foreground so primary controls pass AA without changing the semantic palette.

### 2026-10-31 — T9-A corrections A1–A6 (feature/t9-dashboard)

- Hardened htmx configuration (no eval, local indicator CSS, no inline-style settling, no history snapshot cache, refresh-on-miss) keeping strict CSP without new exceptions.
- Normalized datetime-local filter values, canonical full-page filter URLs via HX-Push-Url, and reload/back/forward-safe filter state.
- Marked private HTML no-store, added the CSRF-refresh contract, and covered logout/history denial with regressions.
- Rebuilt narrow navigation as an overlay panel with a compact header, real menu button state and keyboard handling.
- Bound daisyUI tokens to the agreed sky/slate palette, inlined theme-aware icons, and made charts re-render with readable theme colors.
- Fixed the e2e locator to semantic roles and extended functional browser checks (real Apply, logout+Back, menu geometry, computed colors, charts, console/network).

### 2026-10-31 — T9-A dashboard shell and Overview (feature/t9-dashboard)

- Added the local locked asset pipeline (`package.json`/`package-lock.json`, Tailwind CSS 4 CLI + daisyUI 5 build, vendored htmx/Chart.js, self-hosted Inter/JetBrains Mono WOFF2, bundled Lucide SVG subset with licenses and provenance).
- Added the Jinja2 runtime dependency (pinned in `uv.lock`) and the project-local Playwright dev/browser setup for repeatable browser checks.
- Added session/CSRF-gated browser pages served from the shared analytics layer only: login (JSON to the existing admin endpoint via external JS), authenticated redirects, compact responsive navigation, one global filter bar and the Overview view (KPIs, timeline/status charts with data-table alternatives, referrer/development summaries, coverage/quality notices, honest unavailable timing).
- No second analytics engine, no model transport, no part-B views and no source/upload API.

### 2026-10-31 — external client findings route

- Corrected the external client's `findings` request to use `/api/v1/security/findings`, preserving its CLI option and JSON output key.

### 2026-10-29 — T1 project and runtime baseline (feature/t1-project-baseline)

- Reconciled the planning scaffold onto remote `main` (836769b) on a feature branch; adopted the scaffold README and replaced the remote MIT `LICENSE` with Apache-2.0 per owner decision (ADR 0002, decision 1).
- Added pinned Python 3.12 baseline (`uv`, `pyproject.toml`, `uv.lock`), minimal FastAPI composition root with `/healthz`, validated settings with required secrets and AI disabled, non-root `Dockerfile` and loopback `docker-compose.yml`.
- Added startup and configuration tests (synthetic data only). No analytics, auth, assistant or dashboard code yet.

### 2026-10-28 — planning scaffold

- Added module directories, scoped agent rules and four Muse Code project skills.
- Preserved the supplied v0.4 specification and derived MVP, architecture and acceptance documents.
- Added safe configuration examples and guidance for Muse Code sessions, MCPs and later workflows.
- Recorded the development-tool workflow and routed Muse to it from the root instructions; application/bootstrap work remains pending.
- Added a step-by-step Muse work plan with English prompts, acceptance coverage, review checkpoints and owner-controlled provider/publication steps.
- Application implementation, release validation and external account setup remain pending.

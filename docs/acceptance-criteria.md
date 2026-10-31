# MVP acceptance criteria

All criteria are **NOT IMPLEMENTED / NOT RUN** at scaffold creation. Check a criterion only after repeatable evidence exists. Record command, environment, result and safe artifact references in `verification.md`. A proposed test name is not evidence.

| ID | Criterion | Required verification |
| --- | --- | --- |
| ING-01 | Nginx and Apache NCSA Combined normalize to independently expected fields/metrics | Synthetic fixtures: quoting, escapes, IPv4/IPv6, offsets, invalid bytes, missing fields, unusual methods/HTTP versions |
| ING-02 | Import is streaming, bounded and accounts for accepted/rejected lines | Oversized line/URL/UA cases, invalid-line counts, bounded masked diagnostics |
| ING-03 | Source selection is administrative and read-only | Traversal, symlink escape and arbitrary client path rejection; unchanged source-file evidence |
| ING-04 | Replay of the same file adds no events; legitimate identical requests survive | Import same fixture twice and fixture with identical adjacent requests |
| ING-05 | At least 100k synthetic rows import without a crash | Recorded hardware, duration, peak RAM, accepted/rejected totals and DB size |
| DB-01 | Schema migration, restart persistence and transactional import work | Isolated DB migration/restart/integrity tests, interrupted-batch behavior |
| DB-02 | Backup/restore and configured retention affect only owned data | Restore test; retained/deleted record counts; untouched source logs |
| ANA-01 | Shared analytics have deterministic totals, filters, buckets and stable sorting | Hand-calculated dataset; cross-consumer equality for matching filters |
| ANA-02 | Missing timing is null/unavailable, not zero or invented | Combined-only dataset; API `available: false`; UI notice and no fabricated percentile |
| ANA-03 | Classification/finding claims are explainable and limited | Versioned rule refs, claimed-bot wording, evidence filters, coverage/quality warnings |
| AUTH-01 | Private admin access, password hashing and secure sessions | Login/rate-limit/cookie/CSRF tests behind intended TLS configuration |
| AUTH-02 | Machine tokens are hashed, scoped and site-limited | Missing/invalid/expired/revoked token, missing scope and cross-site 401/403 tests |
| API-01 | Versioned OpenAPI contract exposes bounded read-only analytics | Schema, field types, validated ranges/limits/pagination and deterministic sort tests |
| API-02 | External client can retrieve summary, crawlers and findings without AI | Integration run with chat off, no model key and denied/failing provider transport |
| API-03 | Responses carry site/time/generation/filter/coverage/sample/quality metadata | Contract checks for empty, partial and normal datasets and safe structured errors |
| API-04 | Analytics tokens cannot mutate/import/escalate, expose raw data or proxy a model | Negative integration/E2E tests; no Meta key/model relay in any external response |
| AI-01 | Real permitted Meta model performs a bounded tool-call investigation | Separate authorized smoke call, sanitized output, actual model/tool/evidence IDs |
| AI-02 | Three questions are demonstrable with evidence | AI crawler, 404 with referrer and suspicious-pattern cases; counts/time/source limits visible |
| AI-03 | Tool allowlist, validated arguments and read-only boundaries survive hostile inputs | Adversarial URL/UA/Referer; SQL/shell/scan/firewall/tool escalation attempts cause no execution |
| AI-04 | Assistant failure/cancellation does not break deterministic features | Timeout, offline/provider failure and cancellation with API/dashboard still usable |
| PRIV-01 | No raw logs, original IPs, query secrets or sensitive context leave the egress gate | Capture mocked outgoing prompts, history, tool outputs, retries and replay; assert forbidden data absent |
| PRIV-02 | Real-data requests fail closed on Contributor/unknown/unverified providers/tiers | Fake account/provider metadata and mid-session/replay tier-switch tests |
| PRIV-03 | Privacy defaults minimize storage and local disclosure | HMAC key separation, query discard, path/Referer/UA masking, safe diagnostics and retention tests |
| COST-01 | Model calls obey warning/stop/daily limits and bounded work | Boundary/concurrent/in-flight simulations, timeouts, max tokens/steps and safe usage records |
| COST-02 | LLM budget exhaustion preserves API/dashboard | Mock exhausted budget; no new model call; local English error and successful deterministic queries |
| UI-01 | English central locale catalog covers UI/errors/starters/accessible labels | Locale coverage and English-fallback checks; UTC/display-timezone test |
| UI-02 | Core navigation, login, filters, paginated tables and charts work | Playwright: Overview/Security/Crawlers/Errors/Ask AI/Settings/Data Sources |
| UI-03 | Both themes and keyboard/responsive basics work | Desktop/narrow viewport, system/manual theme persistence, focus and accessible chart table |
| UI-04 | Browser assets are entirely self-hosted | Network evidence without external fonts/CDNs/analytics; CSP-compatible external scripts and local font licenses |
| OPS-01 | Fresh Linux Compose install uses least privilege | Non-root, no privileged mode/socket, loopback/private network, read-only log mount and healthcheck |
| OPS-02 | Persistent data survives restart; offline deterministic features work | Volume restart test and installation with synthetic demo data/provider unavailable |
| OPS-03 | Performance is measured, not assumed | Reproducible 100k/1M synthetic benchmark, import/RAM/DB/query measurements and reference hardware |
| QA-01 | Required tests and independent reviews complete | Actual pytest/httpx/Playwright results; reviewer evidence for parser/auth/tools/retention/authorization |
| QA-02 | UI visual QA supplements automated tests | Desktop/mobile light/dark screenshots, console/network review, no screenshot-only completion claim |
| GOV-01 | Architecture/scope decisions and feature acceptance mapping are recorded | Accepted plan/ADR references; no silent promotion of DECISION/P1/P2 |
| GOV-02 | License, LogWerk provenance and account/data-mode prerequisites are resolved | Owner decisions, upstream notices, verified setup record without credentials |
| GOV-03 | Reviewable delivery and hackathon materials exist | README/install/API/privacy docs, license, synthetic dataset, public-repo approval and 3-minute real-call demo; Official Rules reviewed |

## Definition of done

The feature has an agreed scope, a focused change, relevant passing tests, safe evidence and required independent review. A PR can be prepared for human review. Merge/publication/deployment still require explicit user authorization. If checks are blocked by missing implementation or credentials, record BLOCKED or NOT RUN and the reason.

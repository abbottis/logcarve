# Test and fixture rules

Read the root rules and `docs/acceptance-criteria.md`; map test evidence to acceptance IDs.

- Fixtures are synthetic and use documentation/test addresses and example domains.
- Never import real logs, production DBs, API keys, browser profiles or captured private sessions.
- Use independent, hand-verifiable expected results; avoid assertions that repeat implementation logic.
- Use temporary databases and controlled clocks/timezones; isolate tests from personal settings and the Internet.
- Unit: parser escapes/limits, UTC, missing values, HMAC, bot rules, analytics and egress rules.
- Integration: import idempotency, migrations, auth/scope/site limits, API contracts, privacy and budget boundaries.
- Preserve legitimate identical requests while proving a second import adds no duplicates.
- Inject adversarial text through URL, User-Agent and Referer; verify no unauthorized tool execution or egress.
- Capture outgoing fake-provider requests and assert absence of raw logs, original IPs, secrets and sensitive history.
- Test Standard/Contributor/unknown/provider switches, retry/replay paths and simultaneous budget requests.
- Exercise external API with internal chat disabled, missing model key and a provider that cannot be reached.
- Prove an analytics token cannot invoke imports, escalate scopes, export raw logs or proxy a model.
- E2E: login, navigation, filters, data tables/charts, themes, keyboard access and controlled AI errors.
- Routine runs mock providers; real paid smoke calls are separate and require verified authorized access.
- Benchmarks at 100k/1M rows record hardware, elapsed time, memory and DB size without invented guarantees.
- Report actual command, result and safe evidence; PASS/FAIL/BLOCKED/NOT RUN remain distinct.

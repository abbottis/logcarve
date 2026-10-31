# Security implementation and review checklist

Status: requirements for future implementation; no controls are claimed operational.

| Boundary | Required control | Verification |
| --- | --- | --- |
| Source → importer | Administrative source IDs, approved roots, traversal/symlink defense, read-only files, bounded input | ING-01–04 |
| Imported text → DB/UI | Sanitization, HMAC, parameterized SQL, output escaping, controlled markdown rendering | PRIV-03, ANA-01, UI-04 |
| Browser → admin | Private login, strong password hash, rate limits, secure cookies, CSRF and safe headers | AUTH-01 |
| Client → external API | Hashed scoped tokens, server-side site/time checks, bounded pagination, safe errors | AUTH-02, API-01–04 |
| Analytics → model | Tool allowlist, egress filter, verified tier/provider, no shell/SQL/network tools | AI-03, PRIV-01–02 |
| Model work → billing | Time/token/step limits, concurrency-aware budget handling, fail-safe deterministic service | COST-01–02 |
| App → host | Non-root container, minimal ports/capabilities, no Docker socket, read-only source mount | OPS-01–02 |

Treat URL, User-Agent and Referer prompt injection as data. Requests to run scans, block addresses, modify server configuration or escalate permissions must not cause tool execution. Findings describe suspicions and source limits, never prove attribution or compromise.

Keep secrets, real logs, dumps, retained session exports and provider traces outside the repository and build context. A `.gitignore` is not a secret scanner; add an appropriate scan when CI/runtime dependencies are established. Never print a secret to prove configuration.

Independent review is required for parser, auth, tool-calling, retention and authorization changes. Record severity, file/line evidence, impact and remediation; do not turn a read-only review into unrequested changes. See [privacy/data egress](privacy-and-security.md) and [acceptance criteria](acceptance-criteria.md).

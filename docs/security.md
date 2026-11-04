# Security implementation and review checklist

Status: controls implemented per the acceptance criteria; parser/auth/tool/retention/authorization changes still need independent review before release.

| Boundary | Required control | Verification |
| --- | --- | --- |
| Source → importer | Administrative source IDs, approved roots, traversal/symlink defense, read-only files, bounded input | ING-01–04 |
| Imported text → DB/UI | Sanitization, HMAC, parameterized SQL, output escaping, controlled markdown rendering | PRIV-03, ANA-01, UI-04 |
| Browser → admin | Private login, strong password hash, rate limits, secure cookies, CSRF and safe headers | AUTH-01 |
| Client → external API | Hashed scoped tokens, server-side site/time checks, bounded pagination, safe errors | AUTH-02, API-01–04 |
| Analytics → model | Tool allowlist, egress filter, verified tier/provider, no shell/SQL/network tools | AI-03, AI-05, PRIV-01–02 |
| Backend AI settings | Admin session + CSRF, bounded form parsing, encrypted per-provider keys, no key echoes/exports, token exclusion | AI-06, AUTH-01–02, API-04 |
| Model work → billing | Time/token/step limits, concurrency-aware budget handling, explicit runtime grant, fail-safe deterministic service | COST-01–02, AI-07 |
| App → host | Non-root container, minimal ports/capabilities, no Docker socket, read-only source mount | OPS-01–02 |

Treat URL, User-Agent and Referer prompt injection as data. Requests to run scans, block addresses, modify server configuration or escalate permissions must not cause tool execution. Findings describe suspicions and source limits, never prove attribution or compromise.

Keep secrets, real logs, dumps, retained session exports and provider traces outside the repository and build context. A `.gitignore` is not a secret scanner; add an appropriate scan when CI/runtime dependencies are established. Never print a secret to prove configuration.

Independent review is required for parser, auth, tool-calling, retention and authorization changes. Record severity, file/line evidence, impact and remediation; do not turn a read-only review into unrequested changes. See [privacy/data egress](privacy-and-security.md) and [acceptance criteria](acceptance-criteria.md).

## Known secret-scan findings (reviewed, not allowlisted)

Gitleaks history scans report exactly three findings, all reviewed
false positives; none is a blanket rule, and history is never rewritten.
Raw Gitleaks exit is 1 (findings present) with 3 reviewed fakes and no
actual credentials — not an unqualified 0-findings claim.

- `docs/technical-spec.md:787`: a cost-heading line in the supplied
  German requirements snapshot matches a generic rule. The file is a
  read-only requirement source, never executed or imported.
- `016b458744e33713980b081e7c31c6c56bbe5a58:tests/integration/test_parity_t5a.py:generic-api-key:574`
  (commit SHA verified via `git rev-parse 016b458`; earlier notes
  transcribing this fingerprint differ and are superseded):
  a synthetic pytest `SESSION_SECRET` fixture value in
  `test_unavailable_selection_copy_names_stored_rows`. Root AST review
  confirms test-only dataflow (environment fixture, never a
  credential); no secret value is printed here or elsewhere.
- `986f46e8a8daea2aee86e9484224be47e3fdb022:tests/unit/test_native_http_boundary.py:generic-api-key:32`
  (fingerprint verified via `git rev-parse 986f46e`): a pure
  synthetic fake key sentinel used ONLY through the injected
  fake opener/transport offline tests — never real provider
  credentials and never a real call. No value is printed here or
  elsewhere; the scan rule is not ignored and history is not
  rewritten.

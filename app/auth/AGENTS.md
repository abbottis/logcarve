# Authentication rules

Read the root rules and `docs/security.md`; AUTH criteria require independent review.

- Separate local admin sessions from scoped machine Bearer tokens.
- Hash passwords with Argon2 or an approved current equivalent; hash persisted API tokens.
- Show a new API token once; implement expiry/revocation and avoid tokens in URLs or browser bundles.
- Derive site and scope authorization server-side; never trust client-supplied role claims.
- Rate-limit login and credential use; avoid credential/user enumeration in errors.
- Configure HTTPS session cookies with HttpOnly, Secure and explicit SameSite behavior.
- Require CSRF protection on browser mutations; do not treat SameSite alone as the full design.
- Keep session and HMAC secrets distinct and outside source control; fail clearly when required secrets are absent.
- Grant an analytics token no import, configuration or model-proxy capability.
- Cover unauthorized, forbidden, expired, revoked, cross-site and CSRF cases with integration tests.

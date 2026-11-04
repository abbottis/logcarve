# Configuration examples

These are proposed inputs for the first implementation slice; no loader exists yet.

- `config.example.yaml`: nonsecret product settings, one disabled synthetic source, privacy defaults and disabled chat.
- `../.env.example`: product secrets/environment names; no real credentials or token values.
- `bot_rules.yaml`: empty versioned seed. Add maintained/tested claim patterns with provenance before claiming bot detection.
- `locales/en.json`: initial English string keys, to be expanded with actual UI components.
- `muse-mcp.example.json`: disabled, portable development MCP declarations without credentials. The local user setup additionally authenticates Context7 with a key stored outside this repository. Chrome DevTools is pinned to the tested 1.12.0 release with an isolated headless browser. Never load these as product settings. See `docs/muse-code.md` for the local setup.

The implementation must define/validate config schema and environment precedence, require real session/HMAC secrets, fail closed for unsafe model settings, validate budget relationships and refuse unbounded queries. Example numeric bounds are proposals, not accepted service guarantees. `data_policy_verified` is an administrative gate that must be backed by documented verification, not trusted user input.

Keep actual `config.yaml`, `.env`, secrets, real source paths and user settings untracked. `MODEL_API_KEY` belongs to the product; `META_API_KEY` belongs to Muse Code. Current credit balance, account service tier and actual model availability have not been verified.

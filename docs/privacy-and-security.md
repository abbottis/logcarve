# Privacy and data egress

Status: planned controls and verification gates from the supplied spec, not a legal or operational compliance claim.

## Default local handling

Source logs remain read-only on administrator-approved roots. Parse locally and retain only needed normalized events. Discard query values; minimize Referer to domain/approved path; mask sensitive path/UA content; use secret HMAC pseudonyms. Delete only LogCarve-owned imported data according to configured retention. Use synthetic data in development/CI/demos.

Pseudonymization does not automatically anonymize data. Before real deployments, the operator must resolve the applicable legal basis, provider agreements, retention, locations and transfer requirements. The supplied spec's policy/credit statements are inputs to reverify at use, not an account check performed by this scaffold.

## Encrypted original-IP store (parity T1b, local admin only)

Accepted exception 2026-11-01 (ADR 0003): a local authenticated admin may
view original client IPs. Originals persist ONLY in
`request_original_ips` as AES-256-GCM ciphertext (`cryptography`
50.0.2, fresh 12-byte nonce per encryption, site/source/event identity
as length-prefixed associated data). The key comes ONLY from
`ORIGINAL_IP_KEY` (32 bytes; hex/base64 standard or URL-safe, padded or
unpadded; strict validation, never echoed) and is never
`SESSION_SECRET`, `HMAC_KEY`, `MODEL_API_KEY` or `META_API_KEY`
(equivalent encodings are normalized before the separation check).
Missing/invalid/wrong/tampered keys fail closed with fixed
`private_unavailable:*` codes; there is no plaintext fallback, and
ordinary analytics keep working without a key.

Capture is transient and explicit (`--capture-original-ips` /
`capture_originals=True`, failing before any write without a valid
key): parsers return a `repr`-safe `CapturedOriginal`, never a routine
plaintext field, and only the private encrypt path reveals it. Originals
never reach routine rows, reports, CLI output, the external API, shared
analytics, model tools, exports, errors or logs. Pre-existing rows keep
new enrichment fields NULL until an explicit read-only-source reprocess;
a source id is immutably bound to its site (`source_site_mismatch`
rejects cross-site import/reprocess before any write). Masking modes
(full/suffix-mask/pseudonym-only) are display masking, not anonymity.
Backups hold ciphertext only; key recovery stays separately documented.
Retention cascades private rows with their parent requests and fails
closed when foreign keys cannot be enforced.

## Offline GeoIP country enrichment (parity T5a, PAR-09)

Country lookup is a genuine local MMDB read (DB-IP Country Lite
format, `dbip-country-lite-YYYY-MM.mmdb`) over an operator-mounted
read-only path (`GEOIP_DB_PATH` or `--geoip-db`; empty means
unconfigured): no network request, no paid service, no IP lookup over
HTTP and no country ever inferred from an HMAC pseudonym. The client
address is derived transiently during the import/reprocess
enrichment hook — before the raw address is discarded or encrypted,
even when `ORIGINAL_IP_KEY` is absent — and only a safe ISO 3166-1
alpha-2 code plus lookup source/release/status persists per row.
Private, reserved, loopback, link-local, multicast, documentation,
unspecified and invalid addresses stay `Unknown` without consulting
the database, even if it would return a value. A missing, corrupt,
unreadable or wrong-family database yields fixed `unavailable`
markers while ordinary analytics keep working; an explicitly required
database (`GEOIP_REQUIRED` / `--geoip-required`) fails the run before
any write with the fixed `geoip_unavailable:database_required` code
(never paths, addresses or exception text). Original addresses never
reach routine rows, the external API, exports, errors, model tools or
public Git; the database file itself stays outside Git and outside
the Contributor context. Every page with country-derived results or
filters carries the required CC BY 4.0 credit link
`https://db-ip.com` ("IP Geolocation by DB-IP") via one shared
partial. Export rows always carry the safe country columns, so the
JSON envelope and the CSV `X-Logcarve-Export-Geo` header carry the
same lookup coverage and portable credit with the data — safe
counts, observed sources/releases and display strings only, never
an original address, key or filesystem path. Unknown-only
selections report their own missing per-row source honestly and
never claim the server has no database configured.

## Outbound model boundary

Before **every** provider call, validate allowed provider/model and independently verified effective service tier, authorize site/time scope, minimize payload fields, sanitize identifiers/secrets and enforce work/budget limits. Cover prompt/history, tool results, retries, caches and replay. Default export is metrics, time ranges, rule references and sanitized evidence.

Real-data transmission is blocked for Contributor, unknown tier, unverified provider or a policy switch. `--contributor-mode off` and `MODEL_SERVICE_TIER=standard` express intent only; they do not prove account/service handling. Standard service is not blanket privacy approval. Until checks are documented, only synthetic/nonconfidential data may be sent. Do not expose sensitive project context via coding-agent tools or retained history.

Multi-provider extension (ADR 0004, owner-accepted 2026-11-02): Meta, OpenAI, Gemini and Claude share the same boundary. Tiers stay provider-labeled (Meta/OpenAI Standard, Gemini Paid API, Anthropic API) and Google free/unknown/unverified handling stays blocked: real-data mode requires the provider-specific explicit acknowledgment recorded in backend Settings, and synthetic-only demo mode requires the operator synthetic-source assertion. Provider keys at rest are AES-256-GCM ciphertext under the dedicated `AI_SETTINGS_KEY` (per-provider associated data, strict key separation); pages and errors report only configured/not-configured (or env-managed) state. Mid-investigation provider/model/key/policy changes fail closed; no previous-provider history or secret is replayed elsewhere. A separate explicit bounded runtime usage grant (initially none) gates every real dispatch alongside the preserved T8 smoke ledger.

The optional Open-weight identifier `meta-models/muse-spark-open-1026` has no verified provider/base URL/data policy here. It receives a separate adapter, key, budget and approval gate if adopted.

## Separate data consumers

The external REST API returns minimized authorized analytics without any Meta key or inference proxy. Its client/operator is responsible for any onward transfer to another model provider. The independent API remains available with chat disabled or over budget. Administrative import and retention have separate permissions.

Model errors and telemetry must not log prompts, raw logs or credentials by default. Record safe usage metadata. A local English disabled/error state explains blocked inference; deterministic analytics stay online.

Test evidence: PRIV-01–03, API-04 and COST-02 in `acceptance-criteria.md`. Public end-user/region/age requirements and current provider terms must be checked before expanding the private deployment scope; no such release is performed here.

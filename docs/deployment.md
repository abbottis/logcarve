# Deployment plan

**Checkpoint status, 1 November 2026:** the multistage `Dockerfile`,
base `docker-compose.yml` and standalone `docker-compose.demo.yml` are
implemented. Fresh tracked-export builds, restart persistence, source
read-only checks, backup/restore/retention and isolated offline checks
passed on Linux ARM64 containers. Native Linux x86-64 installation
remains **NOT RUN**. See [verification](verification.md).

For a local synthetic demo use the lifecycle commands in [demo.md](demo.md).
The base Compose file requires operator-provided secrets; do not copy demo
credentials into another deployment. The Node stage builds local assets;
the final runtime is non-root Python and retains license notices.

| Concern | Required behavior |
| --- | --- |
| Host | Linux x86-64; test ARM64 separately before claiming it |
| Access logs | Administrator-configured parent directory mounted read-only; least-privilege file/group/ACL access |
| State | Local persistent SQLite/import/usage data, typically container `/data`; one writer |
| Network | Loopback/private application port; existing reverse proxy with TLS for browser/remote clients |
| Privilege | Non-root, no privileged mode, no Docker socket, minimal capabilities and writable paths |
| Secrets | Protected local `.env`/secret injection; no actual secrets in the image, repo or example files |
| Assets | Built and served locally; no production Node service, CDN or third-party browser telemetry |
| Offline mode | Parsing/DB/dashboard/API function; chat has an explicit unavailable state |

Example host locations from the spec are `/opt/logcarve`, `/var/lib/logcarve`, `/etc/logcarve` and administrator-selected log directories. These are examples, never required hardcoded paths. A parent-directory read-only mount lets future rotation files become visible; it does not grant missing Linux read permissions.

Plesk/HostEurope support must fit an existing reverse proxy without editing production webserver configuration as an installation prerequisite. Do not mount real logs into a development-agent workspace.

Before release: fresh synthetic install, health/readiness, restart persistence, backup/restore, read-only source verification, network/asset inspection and measured 100k/1M-row runs. Record OPS-01–03. Deployment/public exposure and production configuration changes require explicit user authorization.

Operator helpers (coordinator-executed, never installed as services):
`scripts/upgrade_demo.py` performs the in-place store upgrade with a
protected online backup first and hash proofs that all core event
tuples, auth/token/session state and spent allowance survive unchanged
(`--help`/`--dry-run`; posture: AI off, empty model key, non-root,
read-only sources; rollback is image-only, never an automatic backup
restore). The demo's optional original-IP/GeoIP adjunct is
coordinator-owned local wiring only (`artifacts/local-demo-secrets/
original-ip.env` with `ORIGINAL_IP_KEY` + `GEOIP_DB_PATH=/geodata/
<verified-public-db-file>`, plus the public MMDB under
`artifacts/local-demo-geodata/`); ordinary demos omit it and stay
honestly `unavailable`. See [demo.md](demo.md). `scripts/benchmark_synthetic.py` runs the reproducible
100k/1M synthetic benchmark outside Git (expected-vs-observed counts,
import/replay/RSS/DB/query timings, complete export counts or an
explicit 413 above the cap). `logcarve-import follow` /
`replay-archive` provide opt-in incremental follow with durable
checkpoints, generation identity and rotation handling; the browser
starts no watcher. `/readyz` rejects unsupported schemas (fixed
`not_ready` envelope, no file creation); current supported migration
MAX is 9 (migration 0009 adds the runtime-allowance tables the chat
path relies on; 8-stores upgrade in place with data preserved).
Native Linux x86-64 stays NOT RUN; ARM-host amd64 image runs
are EMULATED proof only, with distinct architecture-tagged images.

## Product AI providers (ADR 0004, owner-accepted 2026-11-02)

The backend Settings page (local-admin session + CSRF) selects one of
Meta (`muse-spark-1.3`), OpenAI (`gpt-6-luna`), Google Gemini
(`gemini-3.5-flash-lite`) or Anthropic Claude (`claude-haiku-5-5`)
with its bounded model, data policy and keys. Each provider uses its
genuine native HTTPS endpoint (fixed allowlist, no configurable URL
surface; keys travel in auth headers, never in URLs). Tiers are
labeled honestly: Meta/OpenAI Standard, Gemini Paid API, Anthropic
API. Verified per-model pricing provenance is recorded in
`app/ai/catalog.py` (Meta 2026-10-31, OpenAI/Gemini/Anthropic
2026-11-02 task references).

Safe credential onboarding:

- Generate a dedicated `AI_SETTINGS_KEY` (32 random bytes, base64 or
  hex) and preserve it separately from every other secret. Stored
  provider keys are AES-256-GCM ciphertext bound to their provider;
  backups hold ciphertext only and are useless without this key.
- Enter provider keys in Settings (blank keeps, explicit remove
  deletes) or mount per-provider env fallbacks (`MODEL_API_KEY`,
  `OPENAI_API_KEY`, `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`). Removal
  while an env fallback exists reports env-managed.
- Acknowledge the data policy per provider (real or synthetic-only
  demo mode). Synthetic mode additionally requires the operator
  `AI_SYNTHETIC_SOURCE` assertion; acknowledgments never transfer
  between providers.
- Create the explicit bounded runtime usage grant before any paid
  call: `python -m app.db.cli --db /data/logcarve.sqlite3
  ai-allowance-grant --investigations N --requests M --usd U`.
  There is initially no grant (fail-closed); enabling AI never
  creates one, and settings saves/restarts never reset it. The
  historical T8 smoke ledger is preserved untouched alongside it.

Operator onboarding, provider tiers, troubleshooting, and live-status
notes are collected in the [AI providers guide](ai-providers.md).

## Demo upgrade via the non-root image (coordinator runs, Muse never executes)

The runtime image copies `app/` + `config/` but not `scripts/`, so the
reviewed `scripts/upgrade_demo.py` is fed over stdin through the demo
service (non-root USER 10001, existing `/data` volume, two read-only
source fixtures). Secrets come from the service `env_file`s only; never
hardcode or print credentials, never reset allowances, never restore the
ledger/auth state, no production service required.

```bash
# 1. dry-run: validates everything, mutates nothing (expect verdict dry-run)
docker compose -p logcarve-demo -f docker-compose.demo.yml run --rm --no-deps -T app \
  python - --db /data/logcarve-demo.sqlite3 --backup-dir /data/upgrade-backups \
  --source-root /logs --fixture demo-access.log --fixture demo-rich-access.log \
  --geoip-db /geodata/<verified-public-db-file> --capture-originals --dry-run \
  < scripts/upgrade_demo.py

# 2. explicit online backup (the helper also takes its own protected backup)
docker compose -p logcarve-demo -f docker-compose.demo.yml run --rm --no-deps -T app \
  python -m app.db.cli --db /data/logcarve-demo.sqlite3 backup \
  --dest-dir /data/upgrade-backups --keep 7

# 3. real upgrade + enrichment of the 120 rows (captureOriginals + genuine MMDB)
docker compose -p logcarve-demo -f docker-compose.demo.yml run --rm --no-deps -T app \
  python - --db /data/logcarve-demo.sqlite3 --backup-dir /data/upgrade-backups \
  --source-root /logs --fixture demo-access.log --fixture demo-rich-access.log \
  --geoip-db /geodata/<verified-public-db-file> --capture-originals \
  < scripts/upgrade_demo.py
# expect verdict upgraded, 120 rows, core hash unchanged, auth/ledger preserved
```

Rollback is image-only: redeploy the previous image tag against the
migrated database. Never auto-restore the backup (that would rewind the
spent ledger and auth state); the backup is a protected recovery
artifact retained for inspection.

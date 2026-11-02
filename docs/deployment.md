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
restore). `scripts/benchmark_synthetic.py` runs the reproducible
100k/1M synthetic benchmark outside Git (expected-vs-observed counts,
import/replay/RSS/DB/query timings, complete export counts or an
explicit 413 above the cap). `logcarve-import follow` /
`replay-archive` provide opt-in incremental follow with durable
checkpoints, generation identity and rotation handling; the browser
starts no watcher. `/readyz` rejects unsupported schemas (fixed
`not_ready` envelope, no file creation); current supported migration
MAX is 8. Native Linux x86-64 stays NOT RUN; ARM-host amd64 image runs
are EMULATED proof only, with distinct architecture-tagged images.

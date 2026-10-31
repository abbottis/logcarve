# LogCarve

AI-assisted, self-hosted web access-log analytics for security, crawler activity and development.

**Development checkpoint — 1 November 2026.** The parser, SQLite storage,
deterministic analytics, authenticated REST API, bounded Meta assistant,
browser dashboard and local synthetic demo are implemented. This branch is
an intermediate review snapshot; remaining issues are listed below.

## Run the local synthetic demo

Requires Docker with Docker Compose, host Python 3 and curl. From the repository directory:

```bash
./scripts/demo/init.sh
./scripts/demo/start.sh
./scripts/demo/health.sh
```

Open the [fixed demo window](http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined).
It covers all 30 synthetic events and remains usable after the default
seven-day window has moved beyond the fixture dates.

Log in as `demo-admin`; the generated password is in the protected local
`artifacts/local-demo-secrets/demo.env` file (`LOGCARVE_ADMIN_PASSWORD`).
Never publish that file. The standalone demo forces AI off and an empty
model key. Sources are read-only, the container runs as a non-root user,
and the port is published only on `127.0.0.1:8080`.

See [demo operation](docs/demo.md), [deployment](docs/deployment.md) and
[backup/restore](docs/backup-restore.md). `stop.sh` keeps data; `reset.sh`
replays the verified synthetic fixture without resetting auth or usage.

## What is available

- Bounded Nginx/Apache NCSA Combined parsing with privacy minimization.
- SQLite migrations, replay-safe batch imports, retention and online backups.
- One deterministic analytics layer shared by the dashboard, API and tools.
- Server-side admin sessions and separate scoped, site-bound API tokens.
- Overview, Security, Crawlers, Errors, Ask AI, Settings and Data Sources.
- Locally served assets, themes, charts, table alternatives and pagination.
- An independent [read-only external API](docs/external-api.md) and
  [stdlib client](clients/logcarve_api_client.py) that need no model key.

## Verification and remaining work

The recorded development checkpoint passed 341 unit/integration tests,
15 browser E2E tests, 28 container-browser cases and 23 isolated Docker
smoke checks. These are observed results on macOS ARM64 / Linux ARM64
containers; native Linux x86-64 installation is **NOT RUN**.

The separately authorized real Meta test completed two investigations with
tool evidence. The third stopped at its context bound, so the three-case
AI demonstration remains **incomplete**. Context minimization, a returned
cost-display double count and citation wording remain follow-up work.
The settled usage ledger and execution caps were unaffected by the display
issue. No additional real model calls are authorized by this snapshot.

See [verification history](docs/verification.md), [checkpoint notes](docs/publication.md)
and [next-session tasks](docs/next-session.md). The local demo uses a normal
bridge network; separate internal-network tests establish offline behavior.

## Development and project documents

- [Project rules](AGENTS.md), [MVP](docs/mvp.md), [architecture](docs/architecture.md)
- [Acceptance criteria](docs/acceptance-criteria.md), [decisions](docs/decisions/README.md)
- [Security](docs/security.md), [privacy/data egress](docs/privacy-and-security.md)
- [Development tools](docs/development-tools.md), [Muse Code workflow](docs/muse-code.md)
- [Specification snapshot](docs/technical-spec.md) and [its provenance](docs/spec-provenance.md)
- [Contribution provenance](docs/hackathon-contributions.md)

Original LogCarve code and documentation use [Apache-2.0](LICENSE).
[Third-party components](THIRD_PARTY_NOTICES.md) retain their own licenses.
No LogWerk code or assets have been imported.

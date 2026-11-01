# LogCarve

AI-assisted, self-hosted web access-log analytics for security, crawler activity and development.

**Analytics closeout — 1 November 2026.** The parser, SQLite storage,
deterministic analytics, authenticated REST API, bounded Meta assistant,
browser dashboard and local synthetic demo are implemented. Fundamental
traffic graphs, traffic selection with a 77-rule bot catalog, bot sorting
and drilldowns, and a sanitized request explorer are available from the
reviewed public source branch `feature/traffic-analytics` (clean
application source `e81d2d0`); independent runtime verification is
recorded in the [verification history](docs/verification.md).
No `main` merge, release claim or production deployment is included; the
local persistent demo was updated in place. Inspect `git status` for the
active checkout rather than assuming a branch name.

## Run the local synthetic demo

Requires Docker with Docker Compose, host Python 3 and curl. From the repository directory:

```bash
./scripts/demo/init.sh
./scripts/demo/start.sh
./scripts/demo/health.sh
```

Open the [fixed demo window](http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined).
It covers all 120 synthetic events (30 legacy rows 26–28 Oct plus 90 rich
rows 29–31 Oct) and remains usable after the default seven-day window has
moved beyond the fixture dates.

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
- Overview, Security, Crawlers, Errors, Requests, Ask AI, Settings and Data Sources.
- Fundamental request/error/byte timelines, traffic and bot shares, paths,
  referrers, resource kinds, claimed browser/OS distributions, weekday/hour
  heatmap and pseudonymized client aggregates.
- Traffic selection (all / browser-like / claimed bot / automation /
  unknown), 77-rule named-bot catalog with category/provider/purpose,
  allowlisted bot sorting, named-bot drilldowns and a sanitized paginated
  request explorer.
- Locally served assets, themes, charts, table alternatives and pagination.
- An independent [read-only external API](docs/external-api.md) and
  [stdlib client](clients/logcarve_api_client.py) that need no model key.

## Verification and remaining work

The independently verified analytics closeout passed 428 unit/integration
tests, 22 protected browser E2E tests, a 53/53 synthetic API probe, Ruff
check and format on 152 files, `uv lock --check` on 40 packages, the asset
build with no-external-references check, fully redacted Gitleaks
tracked-export and full-history scans (only the known
`technical-spec.md:787` cost-heading false positive), an 8/0 Docker Compose
candidate run, a 24/0 internal-network offline smoke run and a 32-case
built-image browser matrix on both the isolated candidate and the updated
persistent demo. At the acceptance-readiness anchor `bb272a9`
(reviewed public source branch `feature/acceptance-polish-2026-11-01`,
canonical equivalent `ad6d74f`), the display-timezone catalogue, three
offline AI corrections and the technical local gates are likewise
complete and independently verified: 480 unit/integration tests, 24
protected browser E2E tests, a 121-check offline mock probe, semantic
evidence checks, the 599-zone catalogue, an 8/0 candidate Compose run,
a 24/0 offline smoke run and a 32-case browser matrix on candidate and
persistent demo plus 7/7 timezone acceptance on both. These are observed
results reported by the independent local runner on macOS ARM64 / Linux
ARM64 containers; native Linux x86-64 installation and standalone Linux
host install are **NOT RUN**, and no full release, hackathon or
all-project QA approval is claimed.

Deferred scope stays deferred: gzip, custom formats, live ingestion,
GeoIP, sessions, export/import UX, webhooks and the MCP product server.
The product AI path stays off in the demo (AI disabled, empty model key,
no Internet in offline proof); the separately authorized real Meta test
completed two investigations with tool evidence while the third stopped at
its context bound, so the three-case AI demonstration remains
**incomplete**. The offline context-minimization, exact settled-cost
display and citation/observation corrections are complete and verified;
the settled usage ledger and execution caps were unaffected by the
display issue. No additional real or paid model calls are authorized by
this snapshot. Owner manual acceptance is pending (see the
[acceptance checklist](docs/acceptance-checklist.md)). Muse coding-model
usage is separate from product app caps and the product Standard
data-mode gate.

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

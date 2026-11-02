# Contributing to LogCarve

Thank you for considering a contribution. LogCarve is a self-hosted web
access-log analytics tool in preview for local evaluation.

## Start here

- Read the project rules in [AGENTS.md](AGENTS.md) and the relevant
  guides under [docs/](docs/): at minimum the
  [MVP scope](docs/mvp.md), [architecture](docs/architecture.md),
  [security](docs/security.md), and
  [privacy and data egress](docs/privacy-and-security.md) documents.
- Check the [acceptance criteria](docs/acceptance-criteria.md) and the
  [verification history](docs/verification.md) before changing behavior.
- Use **synthetic fixtures only**. Never add real access logs, raw log
  lines, original client addresses, production configuration, secrets,
  tokens, or personal data to issues, code, tests, or documentation.

## Scoped changes and pull requests

- Keep changes small and scoped to one task: application code, tests,
  and configuration have separate contracts, so change only what the
  task needs.
- Keep ingestion, analytics, API transport, model adapter, and web
  rendering separate, following `docs/architecture.md`.
- Preserve the deterministic analytics layer shared by the dashboard,
  the external API, and the model tools; do not add unrestricted SQL,
  shell access, or new external calls without an approved task.
- Describe the scope, the acceptance criteria addressed, and the checks
  run in the pull request. One focused pull request per change.

## Checks

Run the focused checks that match the change, using the project-local
commands recorded in `pyproject.toml` and `package.json`:

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest tests/unit tests/integration
```

For UI asset changes, use the recorded npm scripts (for example
`npm run build` and `npm run check:external`); see `package.json` for
the current script list. Browser changes need repeatable Playwright
tests where they exist (`uv run --locked pytest tests/e2e` once the
project browser setup is present).

Documentation-only changes do not need the application test suite or
asset build; they need working relative links and correctly formatted
files instead. Please verify links and markup before submitting.

Paid providers and external services are not required for the
deterministic test suite; the dashboard, API, and analytics tests run
offline with synthetic data.

## Provenance and licensing

- Original LogCarve code and documentation are Apache-2.0 (see
  [LICENSE](LICENSE)).
- Upstream LogWerk rule adaptations retain their MIT notice; keep
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
  [contribution provenance](docs/hackathon-contributions.md) up to date
  when touching the rule catalogs.
- Record the provenance of adapted third-party material before
  importing it, and do not copy third-party application code or assets
  without an approved task.

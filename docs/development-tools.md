# Development tool workflow

Recorded on 2026-10-28 following the owner's request to make the development-tool recommendations available to Muse Code. This guide supplies workflow defaults under the root rules. Application architecture, exact dependency versions and implementation approval remain separate decisions.

## Tool responsibilities

| Tool | Project use | When to configure/use |
| --- | --- | --- |
| Git and GitHub CLI (`gh`) | Version control, issues, PRs and CI/check inspection | Establish repository context and usable authentication before remote operations |
| `uv` | Project Python version, `.venv`, dependency groups and `uv.lock` | First authorized application bootstrap |
| pytest | Synthetic parser/analytics/API integration checks | With the first implemented slice and independent expected results |
| Ruff | Python lint and formatting checks | Add to the project development dependencies with Python code |
| Playwright with `pytest-playwright` | Repeatable browser tests for login, filters, tables, themes and keyboard paths | Once a runnable UI exists; install the matching project browser binaries |
| Gitleaks | Secret detection in project files and Git history | Before the first public push and releases; use redacted output |
| Docker Compose, Node/npm and `sqlite3` | Deployment checks, local asset build and synthetic DB inspection | As the relevant application/build files become available |

These are development tools. Keep them separate from the production assistant's allowed analytics tools and from the optional future LogCarve product MCP server.

## MCP baseline

Use Context7 for current library/CLI documentation and Chrome DevTools for interactive browser diagnostics. The local connection/authentication record is in [the Muse guide](muse-code.md); no credentials belong here.

GitHub MCP is optional. Use it only when direct agent-side repository context adds value beyond `gh`. Start read-only with the needed repository/issue/PR toolsets. Credential permissions must independently limit access to `abbottis/logcarve`; toolset filtering alone is not repository authorization. Existing merge/publication approval rules remain in force.

Interactive browser diagnostics complement repeatable Playwright tests. Add a Playwright MCP only for an unmet interactive need. Filesystem, database and SSH MCPs are outside the default MVP tooling; any later addition needs a concrete purpose and preserved application trust boundaries.

## Repository and Python bootstrap

Inspect the actual checkout and current files before initializing anything. The last inspected scaffold had no Git metadata, Python/package manifests or lockfiles. Documentation of this workflow does not authorize a remote write, public push, account login or tool installation by itself; retain authorization already given for an actual setup task.

Choose a tested Python 3.12+ version matching the intended Linux image and record it in `.python-version`. Keep the package definition in `pyproject.toml`, development dependencies in the project environment and resolved versions in `uv.lock`. Maintain lockfiles when intentionally changing dependencies.

For established projects, run checks through `uv run --locked` so a stale/missing lockfile is surfaced rather than silently rewritten. These commands can synchronize the environment from the existing lockfile; use the task's authorized installation/network scope.

Node is for the asset build. Once a package manifest/lockfile exists, use the project's recorded build scripts and pinned dependencies. Do not introduce a separate Node production service for this workflow.

## Check commands after implementation

The following are intended commands once the named tools, manifest/lockfile and relevant tests exist. They are **not passing checks for the current scaffold**.

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest tests/unit tests/integration
```

For a working UI with the project Playwright plugin and browser binaries installed:

```bash
uv run --locked pytest tests/e2e
```

A globally available `playwright` command does not establish the project's Python plugin, matching browser binaries or E2E coverage. Keep the browser/application fixtures synthetic and isolated. See [test rules](../tests/AGENTS.md) and [acceptance criteria](acceptance-criteria.md).

For secret scanning, use an installed, version-recorded Gitleaks binary and limit the scan to the project:

```bash
gitleaks dir . --redact=100
```

Once Git history exists, also scan it:

```bash
gitleaks git . --redact=100
```

Review findings without exposing secret values. Keep reviewed/redacted reports under ignored `artifacts/` when evidence is needed. An ignore file does not replace a secret scan. Do not weaken the scanner's rules merely to obtain a successful result.

Record actual commands and PASS/FAIL/BLOCKED/NOT RUN in [verification](verification.md). Missing implementation, missing dependencies or a test run collecting no tests must not be described as a passing suite.

## Local inventory snapshot

Observed on 2026-10-28; recheck when acting rather than treating this as live machine state:

- Git, `gh`, `uv`, Docker Compose, Node/npm, `sqlite3` and a global Playwright command were available.
- `gh auth status` did not report usable authentication. The project directory had no Git metadata.
- pytest and Ruff were not on the global PATH; the project had no configured development environment yet.
- Gitleaks was not installed. No project bootstrap, tool installation, Git initialization or new MCP connection was performed to record this guide.
- Context7 and Chrome DevTools were configured; see the Muse guide for the tested local setup.

## Primary references

- [uv project execution and lockfile behavior](https://github.com/astral-sh/uv/blob/main/docs/concepts/projects/sync.md)
- [Ruff linter](https://docs.astral.sh/ruff/linter/) and [formatter](https://docs.astral.sh/ruff/formatter/)
- [Playwright Python and its recommended pytest integration](https://playwright.dev/python/docs/intro)
- [GitHub CLI manual](https://cli.github.com/manual/) and [GitHub MCP configuration](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md)
- [Gitleaks scan modes and redaction](https://github.com/gitleaks/gitleaks)

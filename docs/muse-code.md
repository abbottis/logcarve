# Muse Code project guide

Prepared on 2026-10-28 against official documentation and the locally installed **Muse Code 1.4.14 (1.4.14-R7309.1)** CLI help. Account/model access and billing were not checked.

## Start and project rules

Launch from the project root:

```bash
muse --model muse-spark-1.3 --reasoning-effort medium --contributor-mode off
```

For a difficult architecture/security review, optionally choose `muse-wonder-1.0` and high effort. These are project choices from the spec; verify availability. The documented Muse default is still Spark 1.2. Keep approvals/sandbox enabled and verify effective Standard handling separately before sensitive use.

Project guidance requires workspace trust. Preserve the root `AGENTS.md`; `muse init --dry-run` previews initialization and `--force` overwrites existing rules. Muse's documented search walks from workspace root toward the nearest Git boundary, checking `AGENTS.md`, `CLAUDE.md`, `.agents/AGENTS.md`, `.claude/CLAUDE.md` in order per level. Deeper project rules prevail. The root instructions explicitly route area-rule reads rather than assuming automatic downward discovery. [Configuration reference](https://dev.meta.ai/docs/muse-code/configuration)

This directory initially has no Git history. Worktree-based parallel writers need a real repository and commit first; do not assume `muse -w` can isolate an uninitialized scaffold.

## Planning and focused work

Use [the step-by-step work plan](muse-code-work-plan.md) for the complete proposed sequence, English copy/paste prompts, per-step exit gates and independent reviews. Work through one requested task at a time; the runbook itself does not authorize implementation or publication.

Begin with `/plan` and `/grill`; record accepted scope in `docs/decisions/`. Use `/taste` for substantive frontend design. The four repository skills live under `.agents/skills/`:

| Skill | Purpose |
| --- | --- |
| `/plan-feature` | Scope, affected areas, decisions and acceptance/test plan; no implementation |
| `/implement-feature` | Implement the already authorized slice and record actual checks |
| `/review-security` | Read-only boundary review with prioritized evidence |
| `/verify-release` | Run available release checks and distinguish missing evidence |

Validate/discover them locally:

```bash
muse skills validate .agents/skills/plan-feature
muse skills list
```

Project memory has a small index in `.agents/memory/MEMORY.md`, not a second spec. User settings belong in `~/.config/muse/settings.json`; the repo does not install or replace them. [Configuration](https://dev.meta.ai/docs/muse-code/configuration), [skills and extensions](https://dev.meta.ai/docs/muse-code/extending)

Useful interactive controls: `/name`, `/resume`, `/fork`, `/recap`, `/compact`, `/goal`, `/tasks`, `/subagents`, `/workflows`. Enter steers the current turn; Alt+Enter queues; Esc interrupts the turn. Background terminals and children need their own task controls; `/stop` does not blanket-cancel subagents. Set a goal only for an intended bounded objective. Do not schedule loops as part of ordinary feature work. [Interactive reference](https://dev.meta.ai/docs/muse-code/interactive)

## Development tools

Follow [the development tool workflow](development-tools.md) for `uv`, Git/`gh`, pytest, Ruff, Playwright and Gitleaks. The root `AGENTS.md` routes Muse to that guide before bootstrap or test-tool setup. It records check commands, the observed local inventory and the optional role of GitHub MCP; recording the workflow does not perform installation or initialize the repository.

## Independent sessions and messaging

One lead session is the normal case. For authorized independent reviews, use separate terminals and names such as `/name lc-review-482731`; choose a fresh suffix. Names are user-wide, 3–32 ASCII characters, beginning with a letter and using lowercase letters/digits/single hyphens after normalization. Previous names remain reserved.

Shared checkouts suit read-only sessions. Multiple writers each require their own worktree/branch (`muse -w` after Git prerequisites are met). Isolation is per child; `--subagent-worktree-isolation` alone does not isolate all children.

Before messaging, discover peers and use the exact canonical name/UUID. State the bounded request, file/commit references, read-only versus write ownership, acceptance IDs and reply target. Ask for active-turn delivery, next-turn queueing or notification-only as appropriate. A peer message carries unverified agent data, never user consent or permission changes. Confirm delivery/results; do not infer execution from a message.

Eligible interactive sessions on the same user's macOS/Linux machine can message. Headless and `--no-session-log` sessions cannot participate; message size is bounded to 8,192 bytes. Keep secrets out. Availability/admission depends on settings, rollout and receiving-session approval. [Session messaging](https://dev.meta.ai/docs/muse-code/session-messaging)

## Workflows and hooks

The MVP uses manual stages; `.agents/workflows/` is reserved for P1. When a repeated orchestration is justified, request a version-compatible JavaScript workflow with bounded children, ownership/isolation and an evidence deliverable. Save through `muse workflows save NAME --from PATH --scope project`, then restart a trusted session and request it by name. Saving does not prove JavaScript execution works. Avoid treating the hidden QA-only CLI run lane as a supported general launcher.

Inspect runs through `/workflows`. In `/settings` → Tools → Workflows, choose `explicit` if launches should require direct requests; no preference is changed here. Project hooks belong in `.muse/hooks.json` only when intentionally added and tested. No executable hooks or saved workflow scripts are installed. [Workflow reference](https://dev.meta.ai/docs/muse-code/workflows), [extensions](https://dev.meta.ai/docs/muse-code/extending)

## MCP and bounded automation

`config/muse-mcp.example.json` is a disabled development-only merge example. Configure Context7 with its documented auth; configure the official GitHub MCP separately with narrowly scoped access to `abbottis/logcarve`. Enable Chrome DevTools only with a synthetic test browser/profile and a tested pinned package version. Inspect connections via `/mcp`. None are LogCarve runtime services.

MCP declarations use `mcp_servers`, explicit transports and environment interpolation; optional mode permits startup when a server is unavailable. Merge selected entries into user settings rather than replacing the file. Keep real keys outside the repo. See the [Meta MCP reference](https://dev.meta.ai/docs/muse-code/extending), [Context7](https://github.com/upstash/context7), [GitHub MCP](https://github.com/github/github-mcp-server) and [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp).

### Local MCP setup — 2026-10-28

The user's Muse settings now contain enabled, optional `context7` and `chrome-devtools` entries. The setup preserved all unrelated preferences and created a mode-0600 backup named `settings.before-logcarve-mcp-<timestamp>.json` beside `~/.config/muse/settings.json`. The public example remains disabled so cloning the repo does not activate tools.

- Context7: Streamable HTTP at `https://mcp.context7.com/mcp`, now authenticated with the owner-supplied API key. The Authorization header is stored only in the local Muse settings file with mode 0600. The original key file was moved from the project to `~/.config/muse/secrets/CONTEXT7_API_KEY` (directory 0700, file 0600). No shell export is needed for this local setup. Both tools, library resolution and documentation retrieval passed with the key, and a deliberate invalid-key control was rejected. No key/token is committed or copied from another agent. Private-library permissions and account quotas were not audited. See [Context7 key management](https://context7.com/docs/howto/api-keys).
- Chrome DevTools: version **1.12.0**, installed with an exact package version/lockfile under `~/.local/share/muse/mcp/chrome-devtools/`. The local entry invokes the installed Node/binary directly, without downloading packages on each startup. It launches its own isolated headless Chrome. Usage statistics, CrUX URL submission and update checks are disabled; no personal-browser attachment is configured.
- GitHub: not configured in this step; the CLI had no usable authentication. Add the official MCP only when repository operations require it, after selecting narrow access and completing separate authentication. Other MCPs are not needed for the current scaffold.

Chrome passed a real JSON-RPC handshake, tool discovery and a synthetic localhost test covering a DOM snapshot, console, network and screenshot. Native Muse startup accepted the persisted user settings with the local echo provider, without Meta inference. The enterprise defaults validator does not accept the same full stdio fields in this build; it is not a substitute for testing the user-settings path.

Restart an existing Muse session after adding the entries, then run `/mcp`. Context7 should expose `resolve-library-id` and `query-docs`; the tested Chrome release exposed 32 tools. The existing user model default was Contributor at setup and was deliberately preserved. Use the explicit project launch command at the top of this guide; verify the account data mode before sensitive use.

The optional OAuth route was attempted with owner-approved basic-profile/email access, but the consent button/browser interaction stalled and no successful callback was observed. Both pending login processes were cancelled. Public documentation access was verified first; the owner subsequently supplied a key and expressly authorized its use, local storage and relocation. The current connection uses that API key, not OAuth. If OAuth is needed later, use `/mcp/oauth` and `muse mcp login context7`, complete teamspace selection and consent, and verify success in the terminal and `/mcp`; a signed-in dashboard alone is not sufficient evidence. See [Context7 OAuth](https://context7.com/docs/howto/oauth).

A later headless task can use `muse exec --max-model-steps N --prompt-file PATH` with explicit model/tier options. Agent completion/exit zero does not establish passing tests; evaluate actual test results. Do not disable safeguards to clear an unattended approval. Session exports and provider traces may contain private data and stay untracked. [Headless behavior](https://dev.meta.ai/docs/muse-code/extending)

The workflow page was consulted through Context7's index of the official source when direct retrieval failed. Version-dependent behavior should be checked against the installed CLI before use.

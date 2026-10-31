# LogCarve — step-by-step work plan for Muse Code

Prepared: 2026-10-28. Starting point: a documented scaffold with configured development MCPs; application implementation and architecture approval are pending. Reinspect the checkout before starting.

All prompts below are in English. Paste **one prompt at a time**, review the result and follow its exit gate before continuing. Writing or reading this runbook does not execute its prompts or grant their example approvals. It is a proposed execution sequence under the [MVP](mvp.md), [acceptance criteria](acceptance-criteria.md) and root [project rules](../AGENTS.md).

## How to use the sequence

- Use one lead session. Add a separate read-only reviewer at the indicated checkpoints.
- Steps 01–03 produce the grounded plan and settle decisions. Step 04 is the first implementation task.
- After a step passes, save actual evidence in `docs/verification.md` and the next task in `docs/mvp.md`. Never mark an unexecuted test as passed.
- Approval already given for a bounded task remains valid. Ask again only for a material scope change or an action outside that authorization.
- Keep real logs out of development workspaces. Operator account checks must not reveal credentials to the transcript.
- A blocker in product inference does not prevent progressing with deterministic analytics, API and UI work.

| Step | Deliverable | Acceptance coverage |
| --- | --- | --- |
| 00–01 | Trusted session and actual-state inventory | Setup prerequisites; no product criteria completed |
| 02–03 | Proposed plan, settled decisions and explicit owner approval | GOV-01, GOV-02 planning evidence |
| 04 | Reproducible project/runtime baseline | Foundation for OPS-01, OPS-02, QA-01 |
| 05 | Streaming Combined parser and safe normalization | ING-01, ING-02, ING-03, PRIV-03 |
| 06 | SQLite, idempotent import, retention and restore | ING-04, ING-05, DB-01, DB-02 |
| 07 | Shared deterministic analytics and versioned rules | ANA-01, ANA-02, ANA-03 |
| 08 | Authenticated independent REST API and external client | AUTH-01, AUTH-02, API-01, API-02, API-03, API-04 |
| 09 | Independent review of the first vertical slice | QA-01; parser/auth/retention boundary review |
| 10 | Bounded internal assistant using fake providers | AI-03, AI-04, PRIV-01, PRIV-02, PRIV-03, COST-01, COST-02 |
| 11 | Authorized real Meta investigations | AI-01, AI-02; real-provider evidence only |
| 12A–C | Designed, accessible dashboard with local assets | UI-01, UI-02, UI-03, UI-04, QA-02 |
| 13 | Final Compose installation and operations verification | OPS-01, OPS-02 |
| 14 | Measured scale and resilience | OPS-03; final ING-05 and DB-02 evidence |
| 15 | Final independent review and targeted repairs | QA-01; critical-boundary review closure |
| 16 | Release evidence, provenance, documentation and demo | QA-01, QA-02, GOV-02, GOV-03; remaining acceptance audit |
| 17 | Optional, separately authorized publication | Human release decision; no automatic merge/deployment |
| 18 | Local demo video and final submission handoff | GOV-03; owner-controlled publication, terms and submission |

Coverage in this table identifies planned verification, not a completed checklist. If one row is too large, have Muse split it into independently testable tasks without expanding the MVP.

## 00 — Start the lead session

**In your terminal:**

```bash
cd /path/to/logcarve
muse --model muse-spark-1.3 --reasoning-effort medium --contributor-mode off
```

Review and trust the project when Muse asks. Keep the sandbox and approvals enabled. The flags express the intended model/data mode; independently check the effective account/service setting. Use synthetic, nonconfidential context until those checks are settled.

**In Muse, submit these separately:**

```text
/name lc-lead-1028-a
```

```text
/mcp
```

```text
/help
```

Use a fresh session-name suffix if needed; names are user-wide. Confirm Context7 and Chrome DevTools are connected. Project skills require workspace trust. The installed 1.4.14 inventory includes `/plan`, `/grill` and `/taste`; check the local inventory when changing Muse versions. If a project shortcut is unavailable after trust, ask Muse to read the corresponding `.agents/skills/<name>/SKILL.md` and follow it.

**Owner prerequisite:** verify intended Meta account/team, credited balance, model access and effective Standard handling before substantive model use. Never paste keys or private account screenshots into prompts. Product `MODEL_API_KEY` and Muse's development authentication are separate. This runbook does not verify balances or authorize account changes.

**Exit gate:** correct project, intended model, trusted rules and working documentation/browser tools. Resolve setup errors before asking for implementation.

## 01 — Inspect the actual starting point

**Paste into the lead:**

```text
Read AGENTS.md, docs/mvp.md, docs/architecture.md,
docs/acceptance-criteria.md, docs/development-tools.md,
docs/decisions/README.md and docs/muse-code-work-plan.md.
Consult relevant sections of docs/technical-spec.md as requirements.

Inspect the current files, Git state, tool availability and MCP inventory.
Report what exists, what is only proposed, and the first blocking decisions.
Check authentication through safe status commands only; do not inspect or
display secrets, protected Muse settings or real logs.

Return a short inventory and the next planning task. Do not change files,
install packages, initialize Git, call a product model or start implementation.
```

**Expected:** an inventory separating implemented behavior from scaffolding. Installed tools alone do not establish project tests or account authorization.

## 02 — Plan the MVP and first vertical slice

```text
/plan Create a grounded implementation plan for LogCarve using the project
rules and docs. Preserve one site, one configured NCSA Combined source and
both independent integration paths: external read-only REST API and built-in
Meta assistant. Keep deterministic analytics usable with chat disabled.

Recommend the smallest implementation tasks in dependency order. For each,
name affected directories, acceptance IDs, test evidence and dependencies.
Resolve design details for import identity, SQLite migrations, shared query
contracts, admin sessions, scoped tokens, data egress and budget enforcement.
Identify owner decisions on license/provenance, deployment and provider policy.

Use Context7 for specific current library questions. Keep P1/P2 features out.
Write the proposed shared plan to docs/mvp-implementation-plan.md and update
planning documents as needed. Do not create application code, manifests or
containers. Present the decisions and stop before implementation.
```

**Expected:** a decision-complete proposed plan, not a promise that features work. Treat any additional built-in plan artifact as planning state; keep the shared scope/decisions in `docs/`.

## 03 — Challenge the plan, then approve its concrete scope

```text
/grill Stress-test docs/mvp-implementation-plan.md against the technical spec
and acceptance criteria. Focus on legitimate duplicate requests versus replay,
source-root/symlink safety, missing timing, token/site authorization, external
API independence, model data egress and concurrent budget limits.

Ask one material unresolved question at a time. Reuse answers already given.
Record settled decisions and their rationale in docs/decisions/ and the shared
plan. Keep unresolved choices visibly proposed. Do not implement code.
Finish with a bounded scope contract and the first task ready for approval.
```

Resolve the questions as the owner. Confirm license and LogWerk provenance rather than selecting them silently.

**Only after reviewing the actual plan, send an approval such as:**

```text
I approve the scope and decisions recorded in docs/mvp-implementation-plan.md
and the corresponding accepted decision records. Mark only those decisions
as accepted. Carry out implementation one requested step at a time.

This approval includes project-local dependencies and synthetic tests required
by the approved plan. It does not approve paid product inference, public
pushes, repository visibility changes, merges or production deployment.
Continue with the next step only when I submit its prompt.
```

**Exit gate:** accepted decisions and task/test boundaries are recorded. The example above is not approval until you send it after reviewing the real plan.

## 04 — Bootstrap the project and local runtime

```text
/implement-feature Implement only the approved project-bootstrap task.
Inspect Git and any existing abbottis/logcarve remote history before choosing
an integration path. Preserve the scaffold and others' work. If there is no
repository, initialize local version control on a feature branch; if the
remote has history, preserve it and reconcile safely before local commits.
Do not overwrite this directory with a fresh clone or push remotely.

Create the minimal Python/FastAPI composition root, validated configuration,
uv-managed environment, tested Python pin, pyproject.toml and uv.lock.
Add project-local pytest/httpx and Ruff, a minimal healthcheck and meaningful
startup/configuration tests. Add a working non-root Docker/Compose baseline
with loopback exposure, persistent owned data and a disabled synthetic source.
Keep AI disabled and require real secrets for protected application behavior.

Use existing tools; propose/install only missing tools needed for this task
within the approved scope, including a redacted secret scan before committing.
Run the available checks, record actual results and explain the focused diff.
Defer the frontend dependency/build setup to the UI task.
```

**Expected:** a runnable minimal process and reproducible local/container baseline. This is not yet a log-analysis product. If remote history or credentials require an owner decision, prepare the evidence and stop only the dependent work.

## 05 — Build the Combined parser and normalization boundary

```text
/implement-feature Implement the approved NCSA Combined parser task.
Read app/ingestion/AGENTS.md and tests/AGENTS.md. Add independently expected
synthetic Nginx and Apache fixtures for IPv4/IPv6, offsets, missing values,
quoted/escaped fields, malformed bytes, unusual requests and oversized input.

Stream records with bounded memory and explicit field limits. Normalize UTC,
preserve offset context, discard query values, minimize referrers, mask secret
patterns and HMAC-pseudonymize clients. Keep missing duration null.
Enforce administrator-selected source IDs, allowed roots and symlink safety.
Count rejected records with bounded masked diagnostics; never alter sources.

Verify ING-01/02/03 and PRIV-03 with meaningful tests. Defer unsupported
formats and rotation features. Record actual evidence without claiming
database import, bot verification or model integration already exists.
```

**Exit gate:** synthetic fields/counts match independent expectations; unsafe inputs/sources fail safely and no raw-line persistence is introduced.

## 06 — Add SQLite and repeatable batch import

```text
/implement-feature Implement the approved SQLite/import task using the tested
parser. Read app/db/AGENTS.md and app/ingestion/AGENTS.md. Add versioned
migrations, transactional batches, one-writer coordination and import reports.

Provide a local import CLI that accepts configured source IDs. Distinguish
reimporting the same record from legitimate identical requests. Test replay,
interrupted imports, persistence, migration and safe owned-data retention.
Add a reproducible backup/restore procedure and test it on synthetic data.

Import at least 100,000 generated synthetic records. Record reference hardware,
counts, duration, peak memory and database size without invented guarantees.
Verify ING-04/05 and DB-01/02. Keep sources read-only and model calls disabled.
```

**Exit gate:** replay adds no duplicates, identical legitimate requests survive, and restore/retention tests leave source files untouched.

## 07 — Implement the common analytics layer

```text
/implement-feature Implement only the approved deterministic analytics task.
Read app/analytics/AGENTS.md. Use one parameterized repository/query layer
for traffic, status/errors, paths, crawler claims, security candidates,
referrers and measured performance. Version bot/security rules and record
their provenance; do not import LogWerk material without the agreed notices.

Define bounded time filters, bucket edges, stable sorting and quality/coverage
metadata. Carry rule/evidence references with findings. Missing timing must
remain unavailable, never zero latency. User-Agent matches are claims.

Use a small hand-verifiable dataset and test ANA-01/02/03. Keep these services
independent of HTTP, browser rendering and model/provider initialization.
```

**Exit gate:** all consumers can obtain the same reproducible results; partial coverage and unavailable measurements remain explicit.

## 08 — Implement auth and the independent external API

```text
/implement-feature Implement the approved auth/API task using the existing
analytics services. Read app/auth/AGENTS.md and app/api/AGENTS.md. Add the
agreed local-admin session model and separately hashed Bearer tokens with
analytics:read and server-enforced site permissions.

Implement the planned /api/v1 analytics routes and explicit OpenAPI schemas,
validated ranges/limits/pagination, safe errors and response metadata. Keep
admin import and chat separately authorized. Protect browser mutations and
ensure analytics tokens cannot configure sources, import, export raw logs,
escalate scope or relay Meta models/keys.

Add a reproducible external CLI/HTTP client and curl/n8n integration guidance.
Prove summary, crawlers and findings work with chat off, no product model key
and denied/failing provider transport. Include missing/invalid/expired/revoked
token, missing-scope and cross-site tests. Record AUTH-01/02 and API-01–04.
```

**Exit gate:** a genuine external client retrieves authorized JSON with the model completely unavailable. The external API is not a chat wrapper.

## 09 — Independently review the first vertical slice

Pause lead edits and freeze the candidate diff or local commit. Start a second terminal in the same checkout for a **read-only** review:

```bash
cd /path/to/logcarve
muse --model muse-wonder-1.0 --reasoning-effort high --contributor-mode off
```

Wonder is optional and subject to verified access/budget; Spark can perform the review. Give the reviewer a fresh name, for example `/name lc-review-1028-a`, then paste:

```text
/review-security Independently review the current frozen candidate against
docs/mvp-implementation-plan.md and the acceptance criteria for parser,
normalization, source safety, replay identity, SQLite retention/restore,
admin authentication and the external API.

Inspect the actual implementation and tests. Stay read-only with respect to
source/configuration. Use only synthetic temporary data for focused checks.
Return prioritized findings with file/line evidence, triggers, impact and
specific fixes. Distinguish confirmed defects from missing verification.
Do not call a paid product provider or change permissions. Do not approve
merge or deployment. Return the report in this session for the owner to pass
to the lead.
```

Back in the lead, paste the actual report with this prompt:

```text
Address the confirmed findings from the attached independent review within
the approved scope. Add focused regression coverage, rerun affected checks
and record evidence. Preserve effective checks instead of weakening assertions.
Request another independent look at critical boundary fixes before treating
them as release-ready. Do not continue to a new feature in this turn.
```

**Exit gate:** critical defects are fixed and independently rechecked, or explicitly remain release blockers. Repeat this checkpoint after later critical boundary changes.

## 10 — Build the bounded assistant with fake providers first

```text
/implement-feature Implement the approved internal-assistant task using fake
providers only. Read app/ai/AGENTS.md. Reuse the existing analytics services
through typed allowlisted tools, with validated scope/time/size arguments and
traceable tool/filter/result/time/coverage evidence in responses.

Implement provider/model/tier validation, a fail-closed data-egress gate for
prompts/history/tool results/retries/replay, and bounded time/token/tool steps.
Add concurrency-aware usage/budget checks with safe accounting and controlled
failure states. Keep unknown/Contributor/unverified real-data transmission
blocked. No arbitrary SQL, shell, files, URLs, scans or server mutations.

Test URL/User-Agent/Referer injection, outgoing-payload minimization, tier
switches, sensitive-context replay, simultaneous budget requests, cancellation
and provider failure. Prove API/dashboard availability when AI is disabled or
over budget. Record AI-03/04, PRIV-01–03 and COST-01/02. Make no real paid call.
```

**Exit gate:** privacy/tool/budget tests pass with captured mock payloads. Keep Step 11 blocked if provider prerequisites are missing; continue deterministic UI work if useful.

## 11 — Perform the real Meta investigation demo with a bounded allowance

First prepare the test without spending:

```text
Prepare the real-provider smoke test for AI-01/02 without making provider
calls. Verify the implementation and list the remaining operator prerequisites:
account/team access, effective Standard handling, model availability, current
pricing, local usage cap and a protected product MODEL_API_KEY.

Prepare three synthetic cases: declared AI-crawler activity, 404s with an
external referrer and suspicious request patterns. State expected analytics
and the evidence each model response must cite. Report readiness using only
safe metadata; never inspect or print credential contents. If ready, propose
a capped execution with every provider request/retry accounted for.
```

The owner resolves account questions outside the transcript. After reviewing readiness, a **suggested** explicit execution prompt is:

```text
I authorize this prepared synthetic Meta smoke test with muse-spark-1.3 under
verified Standard handling: at most three investigations, twelve provider
requests including retries, and USD 1.00 estimated cumulative product cost.
Use tighter existing limits where applicable and stop before any limit is
exceeded. Do not retry blindly or use a different provider/model/tier.

Run the prepared cases, validate tool/result evidence against deterministic
outputs and record redacted AI-01/02 evidence and measured usage/cost. If access,
pricing or policy is unverified, make no call and report the exact blocker.
```

Change those suggested caps before sending if needed. They are application-side estimates, not a provider billing guarantee, and do not cap the coding sessions. No real customer logs are needed for this proof.

## 12A — Plan and assess the dashboard design

```text
/plan-feature Plan the approved dashboard slice using app/web/AGENTS.md,
the existing API/auth/analytics contracts and UI-01–04. Propose navigation,
shared filters, empty/error/partial-data states, evidence links, centralized
English strings, local assets and accessible light/dark themes.

Use Jinja2/htmx and the agreed local Tailwind/daisyUI/Chart.js build. Split the
work into a tested shell/overview first, then remaining views and chat/admin.
Name the Playwright checks and desktop/mobile visual evidence. Write the
bounded UI plan in docs and present any material unresolved decision before
implementation; do not create frontend code yet.
```

Then, as a separate message:

```text
/taste Review the proposed LogCarve dashboard design against the agreed
information hierarchy, dense data tables, semantic colors, clear focus states,
chart alternatives, both themes and narrow screens. Return concrete design
corrections without implementing files or adding branding/framework scope.
```

Confirm material UI decisions if they are new. A design check does not approve a new framework or replace accessibility tests.

## 12B — Build the dashboard shell and overview

```text
/implement-feature Implement only the approved UI shell/overview subtask.
Read app/web/AGENTS.md and tests/AGENTS.md. Add the needed locked Node asset
build and locally served CSS/JS/fonts/icons with license notices. Preserve
Python as the production runtime and keep scripts compatible with CSP.

Build login, navigation, central English locale keys, explicit timezone/range
filters, paginated overview tables, accessible charts and theme preference.
Escape all log-derived content. Show coverage, empty/error states and missing
timing honestly. Add repeatable Playwright checks and use Chrome DevTools for
synthetic desktop/mobile, light/dark, console and network inspection.
Record actual UI-01–04 evidence for the implemented views only.
```

**Exit gate:** the shell/overview works with local assets, both themes and no model dependency. Do not claim coverage of the remaining views yet.

## 12C — Complete the investigation and admin views

```text
/implement-feature Complete only the remaining approved UI subtask: Security,
Crawlers, Errors, Ask AI, Data Sources and Settings/API access. Reuse the common
filters and deterministic services. Keep administrative source configuration
and import permissions separate from analytics tokens; CLI token management
is acceptable if the approved MVP uses it.

Make AI answers link to their evidence views, and starter questions fill the
input before an explicit send action. Handle disabled/budget-blocked/offline
AI, timeouts, missing timing, partial imports and claimed-bot limitations.
Include the agreed referrer/development summaries without claiming attribution.

Extend Playwright core paths, keyboard/accessibility checks and visual QA.
Prove deterministic pages work without model access. Record UI-01–04 and QA-02
with safe evidence and no new product-provider calls outside an active allowance.
```

## 13 — Verify the final local/container installation

```text
/implement-feature Finish and test the approved deployment configuration for
the implemented application and local asset build. Use docs/deployment.md:
non-root image, no privileged mode/socket, least-privilege capabilities,
loopback/private networking, read-only configured parent log directory and
persistent owned data. Document the TLS reverse-proxy interface.

Run a clean synthetic Docker Compose install, health/readiness checks, import,
restart persistence and offline deterministic API/dashboard behavior. Ensure
MCP development tools and secrets are absent from the image/build context.
Update the real install/configuration and backup/restore instructions.
Record OPS-01/02; report any Linux-specific check not actually executed.
Do not deploy to production or modify Plesk/webserver configuration.
```

**Exit gate:** a reproducible synthetic local install, with Linux validation on an appropriate host/VM. A successful macOS CLI invocation alone is not the Linux deployment test.

## 14 — Measure scale and final resilience

```text
Execute the approved benchmark/resilience verification using the implemented
synthetic generators, isolated databases and test containers. Measure 100k
and 1M records: import throughput, peak memory, database size and representative
filtered query latency. Record hardware, versions, data shape and method.

Repeat the relevant replay, interrupted-import, restart, integrity,
retention/restore, query-bound and LLM-failure/budget checks on this candidate.
Use fake providers; spend no additional model budget. Record OPS-03 and the
final ING-05/DB-02 evidence. Recommend only measured, scoped fixes; no storage
rewrite, multi-site feature or unsupported performance promise.
```

**Exit gate:** reproducible measurements and documented limits. If a defect appears, fix that defect and recheck affected behavior before a broad refactor.

## 15 — Final independent review

Freeze the candidate again. In the separate review session:

```text
/review-security Review the final candidate and its changes since the earlier
review against all acceptance criteria. Trace source access, normalization,
storage/retention, auth/API, browser output, AI tools/data egress and budget
concurrency. Verify the external API cannot export raw logs, escalate scopes
or act as a model proxy, including when the product model is disabled.

Challenge actual test/evidence gaps, container/source permissions, local assets,
provenance and unsupported claims. Stay read-only and return prioritized
file/line findings plus material remaining coverage gaps. Do not approve a
release, expand permissions or call a paid provider.
```

Use the repair prompt from Step 09 in the lead as needed. Security-critical fixes need independent reinspection. A different model can help, but evidence and an independent review context are the essential outputs.

## 16 — Verify release readiness and prepare the submission materials

```text
/verify-release Verify the frozen candidate against every acceptance ID in
docs/acceptance-criteria.md using the actual test/build/install commands.
Reuse valid recorded real-provider evidence; do not spend new inference budget
without explicit authorization. Record PASS/FAIL/BLOCKED/NOT RUN per criterion.

Check reproducible setup, external-client operation without AI, privacy/tier
and budget tests, Playwright, visual evidence, persistence/restore, benchmarks,
license notices and independent-review closure. Update the evidence record
without claiming missing or unexecuted checks passed. Return a prioritized
release-readiness report. Do not publish, merge or deploy.
```

When verified defects are resolved, prepare documentation/demo in a separate turn:

```text
Prepare the approved delivery materials from verified behavior: README,
installation, external API examples, privacy/security limits, synthetic demo
data, reviewed screenshots and a three-minute demo script. Clearly distinguish
the external analytics API from the built-in Meta assistant and old LogWerk
work from new contributions. Preserve actual licenses and notices.

Check the current authoritative Hackathon Official Rules and submission dates;
flag owner eligibility/legal decisions without accepting terms on my behalf.
Use existing real-call evidence for the script; do not record or rerun a paid
demo automatically. Prepare a reviewer-friendly PR title/body and remaining
release blockers locally. Do not push, change visibility, submit or deploy.
```

**Exit gate:** all required acceptance evidence and reviews are complete, or the report explicitly identifies remaining blockers. Submission preparation is not the same as submitting.

## 17 — Optional publication, only after owner review

Review the actual diff, secret-scan results, licensing/provenance, PR description and evidence first. If you choose to push and open a draft PR, send a concrete authorization such as:

```text
I authorize pushing the reviewed current feature branch to abbottis/logcarve
and opening one draft PR with the reviewed description. Verify the remote and
branch match the reviewed candidate before writing. Do not create a different
repository, change visibility, merge, deploy or submit the hackathon entry.
If the target or candidate differs, report it before proceeding.
```

Actual publication, merge, production deployment and hackathon submission have distinct consequences and need their own intended authorization. Do not interpret the runbook text as that authorization.

## 18 — Record the demo and prepare the final submission handoff

Once there is a verified release candidate, ask for the local recording task:

```text
Create the local three-minute LogCarve demo from the reviewed script and
verified synthetic dataset using available recording tools. Show both an
external analytics client working with AI disabled and an evidence-backed
internal Meta investigation. Keep account pages, keys, real logs and personal
browser state out of the recording. Identify prior LogWerk work honestly.

Use a real provider call only under an explicit, currently active allowance;
if another call is needed, prepare its exact capped execution for approval
before recording it. Label any replayed footage/results as recorded rather
than pretending they are live. Validate duration, readability and the final
video/asset paths. Do not upload or publish the recording.
```

Then prepare the exact submission packet:

```text
Prepare a final owner-review packet for the current official hackathon
submission process: verified repository/release reference, local demo video,
project summary, installation instructions, new-versus-reused contributions,
license/provenance and the required form fields. Check current authoritative
rules and dates and flag any unresolved eligibility or release blocker.

Verify the intended repository visibility and video-sharing settings without
changing them. Present the exact material and destinations for review.
Do not upload, accept terms, change visibility or submit on my behalf.
```

**Owner actions:** resolve any rules/eligibility questions, approve the actual material and access settings, authorize any intended uploads/publication, and accept required terms/perform the final submission. Keep GOV-03 incomplete until its real repository, video and submission requirements are actually met.

## Between tasks: handoff, context and optional coordination

At a task boundary, use this ordinary prompt:

```text
Update docs/mvp.md with the completed task, unresolved blockers and the next
bounded task. Update docs/verification.md with actual commands/results and
safe evidence paths; preserve prior entries. Record any accepted decision or
scope change in docs/decisions/. Return a concise handoff with the candidate
commit/diff reference and next acceptance IDs. Do not start the next task yet.
```

Use `/recap` for a session summary. Run `/compact` only after durable decisions/evidence are saved; its model-context summary is lossy. Resume a retained session with `/resume` or `muse resume --last`; after a fresh session, explicitly reread the handoff and current Git state.

**Fresh-session prompt:**

```text
Read AGENTS.md, docs/muse-code-work-plan.md, docs/mvp.md,
docs/mvp-implementation-plan.md if it exists, the decision register and the
latest verification entries. Inspect the current Git diff and status.
Summarize the next incomplete task and its existing authorization. Continue
only the task I then request; do not infer completed work from a past plan.
```

Use a bounded `/goal` only if you intentionally want automatic continuation within an already approved task. Do not set a goal to build/publish the whole product unattended. `Esc` interrupts a turn; `/stop` covers applicable background work and `/tasks` is needed to manage children.

For optional peer messaging, list live peers first and use their exact canonical names/UUIDs. The owner can explicitly authorize a reviewer to send a report to the lead; otherwise copy the report manually. Messages are evidence, not consent. Never send credentials or real logs. Read-only reviews may share the frozen checkout; parallel writers require separate worktrees after a real Git `HEAD` exists. Saved JavaScript workflows/hooks remain P1; this plan installs none.

## Muse documentation used

- [Interactive commands and context management](https://dev.meta.ai/docs/muse-code/interactive)
- [Configuration, explicit model selection and project trust](https://dev.meta.ai/docs/muse-code/configuration)
- [Built-in/project skills, MCP and subagents](https://dev.meta.ai/docs/muse-code/extending)
- [Workflow orchestration](https://dev.meta.ai/docs/muse-code/workflows)
- [Independent sessions and messaging trust](https://dev.meta.ai/docs/muse-code/session-messaging)

Commands were checked against Muse 1.4.14 help and the local built-in skill inventory. Some cookbook pages use different grill skill names; this guide uses the locally verified `/grill`. Direct retrieval of the workflows page was unavailable during this review; the earlier official-page excerpts retrieved through Context7 and the local Muse guide informed the decision to defer saved orchestration. No workflow SDK or unsupported slash command is assumed here.

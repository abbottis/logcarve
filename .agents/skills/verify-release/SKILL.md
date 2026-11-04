---
name: verify-release
description: Verify an implemented LogCarve release candidate against acceptance criteria, using actual test and deployment evidence without publishing or deploying production.
---

# Verify a LogCarve release candidate

Read [project rules](../../../AGENTS.md), [acceptance criteria](../../../docs/acceptance-criteria.md), [deployment plan](../../../docs/deployment.md) and existing [verification evidence](../../../docs/verification.md). Inspect available manifests/commands before running checks.

Run the appropriate implemented parser/analytics/API/auth/privacy/budget suites, Playwright core paths and fresh synthetic container checks when supported by the task/environment. Include external analytics with chat off/no model key, unavailable timing, replay idempotency, scope/site rejection, data-egress/tier tests, persistence/restore and local browser assets. Use Chrome DevTools as supplementary visual evidence.

Routine checks use fake providers. A real Meta smoke call needs verified account/model/data mode and an explicitly authorized cost budget; prepare the synthetic request and validation first if that approval is still needed. Do not infer credentials or spend permission from their presence.

Record exact commands, environment, acceptance IDs and PASS/FAIL/BLOCKED/NOT RUN. Missing code, tools or account access must remain visible. A completed agent task or exit zero is not a passing test suite. Check provenance/license, independent critical reviews and reproducible docs/demo evidence.

Write only safe verification records/artifacts and report release blockers with concrete evidence. Do not change product code, silently install dependencies, publish, merge, submit the hackathon entry or deploy production through this skill.

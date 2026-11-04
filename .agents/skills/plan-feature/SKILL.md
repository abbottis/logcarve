---
name: plan-feature
description: Plan a bounded LogCarve feature against the MVP, open decisions and acceptance criteria, without implementing application code.
---

# Plan a LogCarve feature

Read [project rules](../../../AGENTS.md), [MVP scope](../../../docs/mvp.md) and the relevant [acceptance criteria](../../../docs/acceptance-criteria.md). Inspect existing code and area rules if present.

Use the built-in `/plan` and `/grill` capabilities where available rather than creating a separate planning engine. Produce a concrete slice with scope/non-goals, affected files, dependencies, acceptance IDs, validation and unresolved decisions. Preserve both independent API/assistant paths and the deterministic/privacy boundaries.

For an architecture/scope choice, record alternatives, trade-offs and a proposed ADR or scope contract in `docs/decisions/`. Distinguish required MVP behavior from optional extensions. Do not assume account credits, provider handling or model availability.

Planning may update planning documents; it must not change application code, dependencies, test implementation, deployment configuration or credentials. End with a reviewable plan and any material decisions needed. Respect approval already given in the session; this skill never implies approval to implement the plan.

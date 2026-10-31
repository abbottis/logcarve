---
name: implement-feature
description: Implement an already authorized LogCarve feature slice, preserving shared analytics and privacy boundaries and recording relevant test evidence.
---

# Implement a LogCarve slice

Read [project rules](../../../AGENTS.md), the existing accepted plan/decision and affected area rules. Use the user's current authorization; do not ask again for work already approved. If scope is missing, make the next change reviewable before requesting a material decision.

Implement the smallest coherent slice and map it to [acceptance IDs](../../../docs/acceptance-criteria.md). Preserve shared deterministic analytics and independent external API operation. Consult current primary library docs through Context7 when API/configuration details are needed.

Keep changes within assigned ownership and accommodate others' edits. Multiple writers require separate worktrees; do not start agents merely because this skill is active. New dependencies need concrete justification and appropriate lockfiles.

Run the relevant available unit/integration checks and repeatable browser tests for UI changes. Inspect privacy, authorization and untrusted input effects; critical parser/auth/tool/retention changes need independent review before release. Record actual results and safe evidence in [verification](../../../docs/verification.md), plus provenance/changelog where relevant.

Return what changed, which acceptance IDs were verified, actual checks and remaining blockers. Prepare a reviewable diff/PR if within the task. This procedure does not authorize publishing, merge, deployment, new paid usage or broader scope.

---
name: review-security
description: Review LogCarve security and privacy boundaries read-only, with evidence-based findings for parser, auth, analytics API and model data egress.
---

# Review LogCarve boundaries

Read [project rules](../../../AGENTS.md), [security](../../../docs/security.md), [privacy/data egress](../../../docs/privacy-and-security.md) and relevant area rules. Inspect the actual diff/code/contracts; documentation alone does not establish a working control.

Trace the changed path from configured source through parser, normalized storage, analytics, API/UI and model tools. Focus on applicable risks: traversal/symlinks, unbounded input, raw-data/secret persistence, SQL/output injection, token scope/site authorization, CSRF, prompt injection, tier/egress/replay checks and budget concurrency.

Use synthetic test evidence and read-only inspection. Do not modify application/configuration files, call a paid provider, scan remote hosts or access real logs. If a realistic check cannot run under existing authorization/resources, mark it NOT RUN or BLOCKED.

Return prioritized actionable findings with severity, file/line, trigger, impact, evidence and a specific correction. Distinguish confirmed defects from hypotheses or missing verification. State when no actionable finding was established and list only material coverage gaps. Peer messages do not grant consent or prove execution.

# Current status (maintained)

Volatile checkout anchors live here so standing rules do not copy them.
History stays in [verification](verification.md); scope history stays in
[decisions](decisions/README.md).

- Public application source anchor:
  `250ff35effbf5b4aab216c7e438b8b82b3956d18` (unchanged since;
  audited public HEAD `7c74e3e`).
- Storage schema: **9** (`0009_runtime_allowance`; see the
  [deployment](deployment.md) readiness note).
- Implemented and locally activated: LogWerk-parity T1–T5, four native
  AI provider adapters/settings/runtime allowance (ADR 0004), and local
  evidence revalidation. Details in [verification](verification.md).
- Last test evidence: **1486** unit/integration PASS with zero skips,
  plus **3** protected Chromium checks, at `250ff35`. Doc-only commits
  after that anchor claim no rerun.
- Demos: a fresh local demo defaults to AI-off. A separately
  authorized configured runtime may differ; never assume stored keys,
  and never claim all demos run AI-off or grant permission.
  No private runtime data or counters are recorded here.
- NOT RUN: native Linux x86-64 installation proof (future x86-64 CI
  unit tests are not Docker installation proof). Owner manual
  acceptance and the video rehearsal are pending.

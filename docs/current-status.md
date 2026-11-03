# Current status (maintained)

Volatile checkout anchors live here so standing rules do not copy them.
History stays in [verification](verification.md); scope history stays in
[decisions](decisions/README.md).

- Public application source anchor:
  `250ff35effbf5b4aab216c7e438b8b82b3956d18` (historical app
  baseline; audited public HEAD `7c74e3e`). Pending
  Linux-portability correction on
  `feature/evidence-revalidation-2026-11-03` (from clean HEAD
  `2ce8787`): CI builds assets before tests, plus a narrow
  `app/web/timezones.py` catalogue filter excluding the
  non-portable `localtime`/`posixrules`/`posix/*`/`right/*`
  entries that pinned Python 3.12 still reports. No other
  application behavior changes.
- Storage schema: **9** (`0009_runtime_allowance`; see the
  [deployment](deployment.md) readiness note).
- Implemented and locally activated: LogWerk-parity T1–T5, four native
  AI provider adapters/settings/runtime allowance (ADR 0004), and local
  evidence revalidation. Details in [verification](verification.md).
- Last application test evidence (dated baseline, not a running total):
  **1486** unit/integration PASS with zero skips, plus **3** protected
  Chromium checks, at application source `250ff35`. First actual
  Linux GitHub run at `2ce8787` (workflow_dispatch,
  [run 41614496759](https://github.com/abbottis/logcarve/actions/runs/41614496759)):
  pinned setup/install/Ruff/format/lock PASS; full pytest **1497**
  PASS / **5** FAIL (2 missing built static JS from build-after-test
  ordering, 3 installed-timezone-DB differences), 1502 collected.
  This slice corrects exactly those findings; focused local rerun:
  **19** timezone integration tests PASS (see
  [verification](verification.md)). Full corrected CI runs on GitHub
  after push (coordinator-owned).
- Demos: a fresh local demo defaults to AI-off. A separately
  authorized configured runtime may differ; never assume stored keys,
  and never claim all demos run AI-off or grant permission.
  No private runtime data or counters are recorded here.
- NOT RUN: native Linux x86-64 Docker installation proof (Linux CI
  unit tests are not install/deployment proof). The local demo image
  is unchanged by this slice; no activation authorized here. Owner
  manual acceptance and the video rehearsal are pending.

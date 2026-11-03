# Current status (maintained)

Volatile checkout anchors live here so standing rules do not copy them.
History stays in [verification](verification.md); scope history stays in
[decisions](decisions/README.md).

- Public application source anchor:
  `d375d2743f06e3cb62a5bc574fcb79dfcec128b4` (verified current
  code on `feature/evidence-revalidation-2026-11-03`: CI builds
  assets before tests, plus a narrow `app/web/timezones.py`
  catalogue filter excluding the non-portable
  `localtime`/`posixrules`/`posix/*`/`right/*` entries that
  pinned Python 3.12 still reports. No other application
  behavior changes). Historical baseline
  `250ff35effbf5b4aab216c7e438b8b82b3956d18` (audited public
  HEAD `7c74e3e`) is retained as history only.
- Storage schema: **9** (`0009_runtime_allowance`; see the
  [deployment](deployment.md) readiness note).
- Implemented and locally activated: LogWerk-parity T1–T5, four native
  AI provider adapters/settings/runtime allowance (ADR 0004), and local
  evidence revalidation. Details in [verification](verification.md).
- Last application test evidence: successful Linux GitHub CI push
  [run 41616559340](https://github.com/abbottis/logcarve/actions/runs/41616559340)
  (conclusion success) at application source `d375d27`: pinned
  setup/install/Ruff/format/lock PASS, asset build + external
  asset check before tests, full pytest **1503** PASS with zero
  skips, plus **36** focused local Python and **3** protected
  Chromium checks (counts per receipt; see
  [verification](verification.md)). First actual Linux run at
  `2ce8787` (workflow_dispatch,
  [run 41614496759](https://github.com/abbottis/logcarve/actions/runs/41614496759)):
  **1497** PASS / **5** FAIL, retained as history.
- Secret scan: full-history Gitleaks step success; raw exit 1 with
  **3** reviewed false positives, adjudication PASS — not a
  zero-findings claim.
- Demos: a fresh local demo defaults to AI-off. A separately
  authorized configured runtime may differ; never assume stored keys,
  and never claim all demos run AI-off or grant permission.
  No private runtime data or counters are recorded here.
- NOT RUN: native Linux x86-64 Docker installation proof (Linux CI
  unit execution is not install/deployment proof). The local source
  correction did not deploy and changed neither the existing demo
  image (source unchanged) nor provider keys/allowance; no
  activation authorized here. Owner manual acceptance and the video
  rehearsal are pending.

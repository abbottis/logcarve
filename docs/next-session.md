# Next session checkpoint (1 Nov 2026, acceptance-readiness closeout)

## Where things stand

- Acceptance-readiness closeout at clean application source
  `bb272a9` on the reviewed public source branch
  `feature/acceptance-polish-2026-11-01` (canonical equivalent
  `ad6d74f` on `local/acceptance-readiness-2026-11-01`); inspect
  `git status` rather than assuming a branch name. The
  display-timezone catalogue (A), three offline AI corrections (B)
  and the technical local gates (C) are complete and independently
  verified (see `docs/verification.md`). Earlier analytics slices
  A/B/C were independently verified at `e81d2d0` on
  `feature/traffic-analytics`. Later doc-only commits do not repeat
  application tests. Muse implementation with separate AI-assisted
  planning, review and testing; no exclusive authorship claim.
- Local demo dataset is 120 synthetic rows (30 legacy 26–28 Oct
  byte-identical plus 90 rich 29–31 Oct) under unchanged
  `example-combined`. Reported final gates at this anchor: 480
  unit/integration, 24 protected E2E, 121-check offline mock probe,
  semantic evidence checks (named counts, 72-bin timeseries, sample
  semantics, import quality), 599-zone catalogue, Ruff/lock/diff
  checks, redacted Gitleaks (only the known `technical-spec.md:787`
  false positive), 8/0 candidate Compose, 24/0 offline smoke, 32-case
  browser matrix on candidate and persistent demo, 7/7 timezone
  acceptance on both, exact-image demo update (8080 left running).
  Native Linux x86-64 and standalone Linux host install are **NOT
  RUN**; no release, hackathon or all-project QA approval is
  claimed. Historical real Meta smoke: 2 of 3 investigations
  succeeded, third failed closed — AI-02 stays INCOMPLETE, no new
  paid authorization; demo stays AI-off.
- Fixed entry window for recording:
  `http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined`
- Login guidance: user `demo-admin`; the password lives only in the
  protected local `demo.env` and is never committed, printed or pasted
  into docs, chats or tool queries. Lifecycle:
  `scripts/demo/{init,start,stop,reset,health}.sh` (see `docs/demo.md`).
- Historical analytics-closeout gates (superseded by the anchor
  above): 428 unit/integration, 22 protected E2E, 53/53 API probe,
  Ruff/lock/asset checks, redacted Gitleaks scans, 8/0 candidate
  Compose run, 24/0 offline smoke, 32-case browser matrix. See
  `docs/verification.md` for the full history.

## Precise next work (owner-led, no paid replay)

1. Owner manual acceptance TODAY 1 Nov 2026 with
   [acceptance checklist](acceptance-checklist.md); record
   expected/actual/issues today; planned recording by Tue 3 Nov.
   Nothing auto-accepts on the owner's behalf.
2. Three-minute video rehearsal after acceptance, then
   recording/publication only after owner feedback and audit. No
   merge to `main`, production deployment or GitHub push without
   explicit owner approval; never publish the canonical private
   graph blindly.
3. Real AI proof only if desired, with a new explicit bounded
   authorization (no allowance reset/recreate/restore). The offline
   context-minimization (4000-char bound), exact settled-cost
   display and citation/observation corrections are already complete
   and verified; the third real investigation was not rerun.
4. Platform gap: Linux x86-64 install verification (for a full
   install claim) plus current Official Rules/materials check when
   available.
5. Deferred scope stays deferred: gzip, custom formats, live
   ingestion, GeoIP/sessions, export/import UX, webhooks, MCP
   product server.

## Hard limits and fresh-workspace safety

- Public source plus synthetic fixtures only. Actual runtime secrets
  stay outside this context: never read or request parent private
  runtime, credentials, traces, `demo.env`, token files, real usage
  ledgers or provider keys. Keep `.env`, databases, logs, tokens,
  session exports and provider traces out of version control.
- Product AI stays off in the demo (AI disabled, empty model key, no
  Internet in offline proof). No new real, paid or provider calls are
  authorized; investigation allowance stays exhausted and caps are
  never weakened or reset.
- No push, `main` merge, production deployment or public exposure
  without explicit owner approval. Do not stop or reset the running
  persistent demo without owner say-so.
- Muse coding-model usage (Contributor) is separate from product app
  caps and the product Standard data-mode gate; verify the effective
  account/provider data mode separately before any real-data step.

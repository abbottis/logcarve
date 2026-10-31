# Next session checkpoint (1 Nov 2026, stop point)

## Where things stand

- This publication branch is a consolidated snapshot of the local
  development checkpoint. Original development branches remain local and
  unchanged. See `publication.md` for the publication scope; no `main`
  merge, production deployment or public application exposure is included.
- T10 local demo slice implemented and locally gated (339 passed / 2
  environmental skips both envs; ruff/lock clean; E2E tree 99/99 identical to
  the coordinator's 15-pass). Corrected smoke PASS 23/0 per coordinator rerun.
- T8 real smoke ran ONCE under explicit owner approval and is DONE: A/B
  completed with actual Meta evidence, C failed closed on the history bound.
  AI-01 has real bounded proof; AI-02 is INCOMPLETE (2 of 3), not passed.

## Local demo access (AI-off, running)

- Entry URL: `http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined`
- Login username: `demo-admin` (password only in the protected `demo.env`)
- Lifecycle: `scripts/demo/{init,start,stop,reset,health}.sh` (see `docs/demo.md`).
- Protected credential paths (0600 files under ignored `artifacts/`,
  never committed, never printed):
  - `artifacts/local-demo-secrets/demo.env` (demo-only session/HMAC/admin password)
  - `artifacts/local-demo-secrets/demo-token.txt` (scoped demo-client token)
  - `artifacts/real-meta-smoke/` (real-run ledger/results/state; do not reset)
- Do not stop/reset the running demo without owner say-so. Product key:
  used only server-side by the coordinator for the authorized run; never
  copied/printed; Muse did not read it; no further use authorized.

## Precise next offline tasks (no paid replay, caps never weakened)

1. C history minimization: typed evidence/history hits HISTORY_MAX_CHARS 4000
   before second dispatch. Minimize while retaining filters/coverage/
   reproducibility; reproduce with synthetic fake responses only.
2. Cost display double-count: final step counted twice in returned usage
   (ledger/settlement correct). Fix with an offline regression comparing
   per-step charges, aggregate usage, and allowance.
3. Citation quality: model prose sometimes uses tool names as citations or
   mislabels window observation time; structured evidence IDs exist — review
   wording separately.

## Hard limits carried forward

- Allowance exhausted (3/3 investigations, 5/12 requests, $0.039557 charged):
  NO further real/provider work is approved. Never create fresh state or
  reset/restore usage to retry. C stays failed-closed.
- Native Linux x86-64 install: NOT RUN (ARM64 initial demo only).
- No release claim: no video publication, submission, purchase, Plesk/prod
  change, or `main` merge without explicit owner approval.
- Final coordinator gates (in verification log): clean 341/0, E2E 15 pass,
  28-case container matrix, corrected smoke 23/0. Nothing pending except
  owner-directed next work.

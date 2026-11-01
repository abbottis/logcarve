# Local demo profile (T10, synthetic data, AI off)

Loopback-only persistent demo for the 3 November recording. No real logs,
no model key, no provider contact, no public exposure.

## Entry URL (use this on recording day)

The default 7-day window ages the fixed October fixtures out by 3 Nov, so
open the explicit custom window covering the combined 120-row synthetic
dataset: 30 T8 rows (26–28 Oct 2026) plus 90 rich Slice C rows
(29–31 Oct 2026, outside the T8 window, same `example-combined` source):

```text
http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined
```

## Lifecycle (run locally with access to Docker)

```bash
./scripts/demo/init.sh    # one-time: exclusive 0600 demo secrets (refuses overwrite)
./scripts/demo/start.sh   # build, start, verified synthetic seed (idempotent)
./scripts/demo/health.sh  # public /healthz + gated /readyz (private session)
./scripts/demo/stop.sh    # stop, keep data (never down -v)
./scripts/demo/reset.sh   # nondestructive verified reseed (replay-zero proof)
```

What each step guarantees:

- `init` creates `artifacts/local-demo-secrets/demo.env` (0700 dir, 0600
  files) only when absent, refuses symlinks, never reads the product key.
- `start` builds the multistage image, waits for `/healthz`, then seeds the
  combined 120-row dataset: the untouched 30-row T8 fixture (fingerprint
  must equal the authoritative digest `d765393f…ebeb65`) plus the 90-row
  rich fixture (`b9479a8e…52ca45f`); foreign stores are refused untouched,
  and legacy T8-only stores upgrade additively (T8 rows never rewritten).
- `health` asserts `ai_enabled=false`, unauthenticated `/readyz` → 401
  (gating proof), and private admin `/readyz` → ready. No secret is printed.
- `reset` re-imports (0 inserted / 30 replayed for T8, 0 / 90 for rich) and
  restarts; users, tokens, import history, spend and allowance state are
  preserved. It never removes the demo volume, restores an old ledger, or
  edits source logs.

## Browser login and external client

- Log in as `demo-admin` with the password stored in
  `artifacts/local-demo-secrets/demo.env` (`LOGCARVE_ADMIN_PASSWORD`).
- A scoped `analytics:read` token for `default` is issued at seed time to
  `artifacts/local-demo-secrets/demo-token.txt` (0600, shown once, never
  printed). Use it with the external client while chat stays off:

```bash
export LOGCARVE_API_TOKEN="$(cat artifacts/local-demo-secrets/demo-token.txt)"
python clients/logcarve_api_client.py --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-26T00:00:00+00:00 --to 2026-11-01T00:00:00+00:00 --endpoint all
```

Bearer tokens cannot reach `/api/v1/chat/ask` (401, no model proxy), and
asking with a session while AI is off returns 409 with deterministic
analytics intact.

## Isolated candidate verification (before any original-demo change)

`scripts/demo/verify_candidate.sh` proves the Slice C dataset on a
tracked-only export before the persistent demo is ever touched
(coordinator executes; Docker is required, so Muse never runs it):

- Unique project `logcarve-demo-candidate` on loopback port 8091 with a
  temporary owned runtime (secrets, compose file, volume, network); any
  preexisting candidate resource or a listener on 8091 refuses the run.
- Builds from `git archive HEAD`, pins both authoritative fixture digests,
  seeds 30 + 90 rows under the unchanged source identity, requires probe
  `SEEDED` with 120 rows, proves replay-zero (0/30, 0/90), restarts, and
  re-verifies — then tears down only run-owned resources.
- Own generated secrets only; the owner base `.env`, the product model key
  file, the persistent demo project/secrets, and the Docker socket are
  never read or mounted. AI stays off with an empty model key throughout.

Only after the candidate passes does the coordinator take an online
backup plus image/commit references and perform the reversible local
demo update; the published snapshot and original live demo stay unchanged
until a tested candidate exists.

## Safety invariants

Standalone `docker-compose.demo.yml`: no owner `.env` inheritance, forced
`AI_ENABLED=false`, empty model key, unverified-policy flags false.
Non-root image user, no privileged mode, no Docker socket, read-only
synthetic source mount, project-scoped volume/network. Reset/seeding
refuses foreign data and preserves all auth/spend/allowance state.

## Offline labeling (honest)

The persistent demo itself runs on the default bridge network — it is
loopback-published and makes no provider calls (AI off, no key), but it is
NOT air-gapped. The offline proof is separate: `scripts/smoke_demo.sh`
runs the same image on an `internal: true` network (host ports unpublished
by the engine) and executes every API/client/restart/backup check inside
that network via `scripts/smoke_offline_probe.py`. Do not call the
persistent demo offline; cite the isolated smoke result instead.

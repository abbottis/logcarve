# Local demo profile (T10, synthetic data, AI off)

Loopback-only persistent demo for the 3 November recording. No real logs,
no model key, no provider contact, no public exposure.

## Entry URL (use this on recording day)

The default 7-day window ages the fixed October fixtures out by 3 Nov, so
open the explicit custom window covering the full 30-row synthetic fixture
(26–28 Oct 2026, all three investigation windows):

```text
http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined
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
  known 30-row fixture (import fingerprint must equal the authoritative
  digest `d765393f…ebeb65`); foreign stores are refused untouched.
- `health` asserts `ai_enabled=false`, unauthenticated `/readyz` → 401
  (gating proof), and private admin `/readyz` → ready. No secret is printed.
- `reset` re-imports (0 inserted / 30 replayed) and restarts; users, tokens,
  import history, spend and allowance state are preserved. It never removes
  the demo volume, restores an old ledger, or edits source logs.

## Browser login and external client

- Log in as `demo-admin` with the password stored in
  `artifacts/local-demo-secrets/demo.env` (`LOGCARVE_ADMIN_PASSWORD`).
- A scoped `analytics:read` token for `default` is issued at seed time to
  `artifacts/local-demo-secrets/demo-token.txt` (0600, shown once, never
  printed). Use it with the external client while chat stays off:

```bash
export LOGCARVE_API_TOKEN="$(cat artifacts/local-demo-secrets/demo-token.txt)"
python clients/logcarve_api_client.py --base-url http://127.0.0.1:8080 --site default \
  --from 2026-10-26T00:00:00+00:00 --to 2026-10-29T00:00:00+00:00 --endpoint all
```

Bearer tokens cannot reach `/api/v1/chat/ask` (401, no model proxy), and
asking with a session while AI is off returns 409 with deterministic
analytics intact.

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

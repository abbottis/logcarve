# 3-minute demo script (English, synthetic data, AI off)

Recording-day entry URL (paste as-is):

```text
http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined
```

Start the stack before recording: `./scripts/demo/start.sh` (healthy when
`/healthz` answers). Log in as `demo-admin` (password in the protected local
`artifacts/local-demo-secrets/demo.env`, never shown on screen).

## 0:00–0:30 — What this is

"LogCarve is a self-hosted access-log analysis tool. This demo runs fully
offline on synthetic Nginx logs: thirty rows from 26 to 28 October, one site,
one read-only source. The assistant is off on purpose — everything you see
comes from the same deterministic analytics layer that also serves the API."

Show: Overview totals (30 requests), the custom window in the filter bar,
Europe/Berlin display timezone.

## 0:30–1:20 — Three synthetic stories

1. "Claimed AI crawlers visited our docs." Crawlers view: GPTBot/Claude
   claim counts with rule references. "Claimed, not verified — logs alone
   cannot prove who really fetched."
2. "Something linked to pages that do not exist." Errors view: the 404
   group with referrers. Open one evidence link; it replays the same read.
3. "One client probed sensitive paths." Security view: findings with rule
   IDs worded as investigation candidates, never verdicts.

## 1:20–2:10 — Roundtrip and external client

"Filters survive navigation." Click Settings, then Data Sources, then back
to Overview — site, source, window and timezone are preserved.

"Machines get the same answers without chat." Terminal: run
`clients/logcarve_api_client.py --endpoint all` for the window; read the
summary totals aloud (30 requests). "Bearer tokens are scoped and
site-limited; they cannot import, escalate, or reach the model."

## 2:10–2:50 — Honest limits

"Missing timing shows as unavailable, never zero. Counts carry coverage and
quality metadata. On AI: the authorized real smoke ran once — investigations
A and B completed with actual model evidence, C failed closed on a history
bound, so two of three demonstrations exist and no real-AI take is recorded
here. The allowance is spent and no further model work is approved. Native
Linux x86-64 verification is still outstanding; this runs on ARM64 loopback."

## 2:50–3:00 — Recovery

Stop and restart the demo (`stop.sh`, `start.sh`): the same 30 rows return.
"Backups restore into isolated paths; retention only deletes LogCarve-owned
data; source logs are never modified."

## Do not show

Real logs, IPs, tokens, passwords, the product key file, or any provider
dashboard. No take implies a real AI answer, a latency guarantee, native
Linux proof, or a public release.

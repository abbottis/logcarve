# ADR 0003 — LogWerk parity scope and privacy exceptions

- Date: 2026-11-01
- Status: **Accepted** 2026-11-01 by owner via `artifacts/task-inputs/logwerk-parity-owner-scope.md`. Sufficient for the T1–T5 stages in `docs/logwerk-parity-plan.md`; no new approval loop for those stages.
- Origin: new LogCarve implementation by Muse (Muse Spark 1.3 Contributor, medium, protections ON). Upstream LogWerk `d7ab01c` provenance stays in `THIRD_PARTY_NOTICES.md`; any further copied rules need exact source + MIT notice. No internal-tool origin labels.

## Accepted exceptions (bounded to this parity scope)

1. Local authenticated admin may view original client IPs; default is full view with selectable suffix masking (IPv4+IPv6) or pseudonym-only. This supersedes the earlier blanket no-local-IP constraint for this feature only.
2. Technical request-journey grouping (HMAC-client + sanitized UA, 30-min gap) is permitted; it does not supersede the ban on inferring people, true sessions, conversions, indexing, rankings, or training use.
3. Additional enriched storage (sanitized referrer path/host/protocol, cache, timing, MIME, TLS, HTTP version, host, journeys, offline country) is permitted under the existing minimization rules.
4. Gzip ingest, measured-timing presets, bounded admin custom format mappings, and opt-in incremental follow/rotation are permitted; the old MVP deferrals no longer block them.

## Invariants preserved

External API, analytics exports, error messages, model tools/prompts/history, public Git, and telemetry never carry original IPs or raw lines. API tokens cannot access originals. Source logs stay read-only. Model Standard gates, budget caps, and the 120/auth/usage/allowance demo protections are unchanged.

## Nonrecoverable data and reimport

Discarded query values and pre-HMAC original addresses cannot be reconstructed. Old records gain enrichment only through read-only source reprocess without duplicate events or altered legacy HMAC/totals. At-rest originals use proven authenticated encryption with key separation; key absent means fail-closed unavailable while deterministic analytics keep working.

## Acceptance impact

New criteria `PAR-01`–`PAR-10`; extends ING/ANA/AUTH/API/PRIV/DB/UI/OPS as mapped in `docs/acceptance-criteria.md`. Exclusions (no UI import, no translations) stay non-goals.

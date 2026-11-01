# LogWerk parity metrics (T2a slices C/D) — definitions and provenance

Status: implemented 2026-11-01 on `feature/logwerk-parity-2026-11-01`
(shared service/query layer only; HTTP wiring is T3, journeys T2b).
All consumers (future dashboard, REST API, bounded tools) share the
functions in `app/analytics/service.py` over `app/analytics/queries.py`,
so equal filters always yield equal results.

## Units and precision

- All timings are **milliseconds** (`response.units == "milliseconds"`).
- Stored values are REALs parsed from seconds with finite-nonnegative
  validation; zero is a valid observation, missing (`NULL`) is never
  zero and never contributes to any average/percentile.
- Averages come from SQL `AVG` with a finiteness guard: individually
  finite large timings that overflow a naive `SUM` yield
  `average_ms: None` plus a `<column>_average_unavailable:overflow`
  warning — never `Inf`/`NaN` (JSON-safe by construction; tested with
  two ~1e308 ms observations).
- Legacy Combined scopes honestly report `latency_available: false`
  with `measured: 0` (PAR-03 `available: false`).

## Percentile definition (documented contract)

Ascending measured values `v[0..n-1]` (NULLs excluded, ties kept),
rank `r = q * (n - 1)`,
`v[floor(r)] + (v[ceil(r)] - v[floor(r)]) * (r - floor(r))`
(median `==` P50). Computed with single-row SQL order statistics over
the entire filtered scope — never sampled, never a full `fetchall` of
durations. The `(hi - lo)` form plus a finiteness guard keeps
near-float-ceiling interpolation stable.

## Request vs upstream duration

- `request_time_ms` is the measured request latency
  (Nginx `$request_time`).
- `upstream_time_ms` is the **aggregated total** of all logged upstream
  legs (`$upstream_response_time`, comma/colon/space separated),
  with `upstream_count` legs. A partial multi-leg value such as
  `"0.100, -"` means one leg logged no timing: the complete total is
  **unavailable** (`NULL`, no count inferred, never zero) while the
  event and its separately measured request duration are preserved.
  Parser, line, import, reprocess and service layers agree (tested).

## Cache

- `hit_ratio = HIT / cache_measured`, where `cache_measured` counts
  rows with a logged `cache_status`. Absent rows render `Unknown` and
  never enter the denominator (documented in
  `hit_ratio_denominator`).
- Status **304** counts normal HTTP cache validation
  (`not_modified_304`), reported separately — never automatic crawl
  waste.

## MIME, version, TLS, host

- `mime_type` is the measured logged media type (parameters stripped,
  lowercased); the resource kind is the documented path-extension
  heuristic. The cross-tab exposes divergence (e.g. logged
  `image/png` on an extensionless path lands on kind `page`).
- Missing HTTP version / TLS / logged host render `Unknown` (exact
  all-row `GROUP BY`, stable requests-DESC/value-ASC order).

## SEO (slice D)

- Bot 3xx/4xx/5xx groups attribute each row to exactly one configured
  rule/provider via the ordered 77-rule classifier (first match wins),
  with exact counts/bytes and `bot` + `path_prefix` + `status_class`
  drilldown selectors. Claims only.
- **AI-only** = paths observed for configured `ai_crawler` rules and
  NOT observed for other traffic in the same site/source/time/base
  scope. Bot/category/provider/purpose/traffic selectors are
  **removed** when building the comparison universe (reported under
  `comparison.selectors_removed`) so an AI-only filter cannot
  trivially prove absence. Every answer carries the comparison
  scope/coverage, the absence caveat, and a `vacuous` flag when the
  universe holds no non-AI traffic. No indexing, training-use or
  ranking claim — ever.
- Referrer-path → 404 uses only sanitized `scheme + host + path`
  (query values, userinfo, ports and secrets never stored). Own
  domain/aliases (site hostname + stored source aliases) split
  internal from external. Matching: lowercase hostname equality;
  only `http`/`https` schemes stored (dangerous schemes can never
  appear as clickable); IDN compares in stored encoded form.

## Provenance

- Enrichment policy tag `t1b.1` (plus custom fingerprints); old rows
  gain enrichment only via read-only source reprocess.
- Bot catalog: `config/bot_rules.yaml`, 77 rules (17 `ai_crawler`),
  asserted untouched by test.
- New metadata filters (logged host, HTTP version, MIME, cache, TLS,
  timing availability/range) are validated/bounded in
  `AnalyticsFilter`, bound as parameters, and carried through filter
  serialization (`_filter_dict`) consistently; legacy callers
  compatible (all default `None`).
- **No schema change in T2a**: all columns exist since T1b migration
  0005; existing pinned migration tests (`applied == (1..5)`) pass
  untouched. New read indexes deferred to a later stage with its own
  migration.

## T1b preflight closed by this slice (frozen `9b61423` rechecked)

- `CapturedOriginal` is no longer a dataclass: it holds a Pydantic
  `SecretStr` in a slotted non-dataclass, so `dataclasses.asdict`
  raises `TypeError` on a bare capture; nested `asdict`, pickle bytes
  and JSON carry no plaintext (tested); `reveal()` feeds only the
  proven encrypted channel.
- Source binding is enforced **inside** the write transaction
  (`ensure_source_locked` / `check_source_binding_locked`): an
  injected foreign registration after the precheck raises
  `source_site_mismatch` and rolls back site/import/rows/private
  (deterministic regression test).
- Already-bound sources gain validated alias metadata through
  `update_source_hosts` (only the `allowed_hosts` column, guarded by
  site; core/site/auth/ledger preserved), persisted on import and
  reprocess so later internal/external referrer reports classify
  correctly (tested, incl. secret-bearing referrers).

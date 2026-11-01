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
- The shared `summarize().duration` block and
  `performance_overview().latency_*` agree: both follow measured
  `request_time_ms` (valid zero included, missing never zero). When no
  request timing exists the reason is `no_measured_request_timing`; an
  explicitly stored legacy `duration_ms` value is acknowledged
  separately (`legacy_measured` with a `legacy_duration_only:...`
  reason) without rewriting legacy core rows.

## Percentile definition (documented contract)

Ascending measured values `v[0..n-1]` (NULLs excluded, ties kept),
rank `r = q * (n - 1)`,
`v[floor(r)] + (v[ceil(r)] - v[floor(r)]) * (r - floor(r))`
(median `==` P50). Computed with single-row SQL order statistics over
the entire filtered scope — never sampled, never a full `fetchall` of
durations. The `(hi - lo)` form plus a finiteness guard keeps
near-float-ceiling interpolation stable.

## Slow endpoints

- Every sort (`avg_desc`, `requests_desc`, `max_desc`, `p95_desc`)
  ranks the whole candidate set exactly in SQL with stable tie-breaks.
  `p95_desc` computes each path's exact P95 with integer
  order-statistic arithmetic inside one window-aggregate statement and
  pages the ranked result (`p95 DESC, path ASC`), so a rare slow path
  is never hidden by a frequency preselection; only the requested page
  crosses into Python (never a `fetchall` of every duration or path).
  History: the first T2a cut ranked only the 200 most-measured paths
  and misreported a global sort; corrected before T2b with a 201-path
  rare-slowest-first regression plus tie/filter/zero/large probes.

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
- Distributions are bounded (default top-100 known groups per widget,
  explicit per-call `limit`/`offset` — never an unrelated widget's
  paging fields) with exact whole-scope totals: `shown`,
  `total_values`, `truncated` and an exact `other_requests` remainder
  keep every row counted (`sum(shown) + other == total`); page through
  for the complete distribution. The `HIT` numerator and the
  cache denominator are whole-scope exact even when `HIT` falls
  outside the displayed top page.
- Missing values render a separate count-correct `Unknown` bucket that
  is always reported last (stable requests-DESC/known-value-ASC
  ranking, NULLs never interpolated into the order), including at
  count ties and past the display bound. No MIME/version is guessed,
  no zero fabricated.

## SEO (slice D)

- Bot 3xx/4xx/5xx groups attribute each row to exactly one configured
  rule/provider via the ordered 77-rule classifier (first match wins),
  with exact counts/bytes and `bot` + exact `path_exact` +
  `status_class` drilldown selectors. The legacy `path_prefix` remains
  available as a widening prefix exploration. Claims only.
- **AI-only** = paths observed for the *selected* AI candidates and
  NOT observed for other traffic in the widened comparison universe.
  The caller's bot/category/provider/purpose/traffic selectors stay on
  the candidate side; ONLY the comparison universe widens by dropping
  them (removed names under `comparison.selectors_removed`), so an
  AI-only filter cannot trivially prove absence — a shared browser
  path always contributes other-traffic rows and can never be AI-only.
  Both scopes carry their own filters and coverage (`candidate.*` vs
  `comparison.*`). Incompatible selectors (traffic outside
  `all`/`claimed_bot`, or a bot/category/provider/purpose matching no
  AI rule) raise instead of being silently ignored. Every answer
  carries the absence caveat and a `vacuous` flag when the universe
  holds no non-AI traffic. No indexing, training-use or ranking
  claim — ever.
- Referrer-path → 404 covers internal AND external referrers together
  (each row labelled; `relation: all/internal/external` narrows in SQL
  with matching totals instead of filtering a fetched page) using only
  sanitized `scheme + host + path` (query values, userinfo, ports and
  secrets never stored). Totals come from an exact grouped subquery
  (no delimiter-collision tuple encoding); every grouping key orders
  ties deterministically (requests DESC, host ASC, scheme/path
  NULLS LAST, target ASC). Own domain/aliases (site hostname + stored
  source aliases) split internal from external. Matching: lowercase
  hostname equality; only `http`/`https` schemes stored (dangerous
  schemes can never appear as clickable); IDN compares in stored
  encoded form.

## Provenance

- Enrichment policy tag `t1b.1` (plus custom fingerprints); old rows
  gain enrichment only via read-only source reprocess.
- Bot catalog: `config/bot_rules.yaml`, 77 rules (18 `ai_crawler`),
  asserted untouched by test.
- New metadata filters (logged host, HTTP version, MIME, cache, TLS,
  timing availability/range) are validated/bounded in
  `AnalyticsFilter`, bound as parameters, and carried through filter
  serialization (`_filter_dict`) consistently; legacy callers
  compatible (all default `None`).
- The bounded exact `path_exact` selector reproduces one stored path
  group (SEO/AI drilldowns); the legacy `path_prefix` remains a
  widening exploration. Filter contradictions (exact-vs-prefix,
  status-vs-class, timing bounds) reject with `ValueError`.
- CLI `--host-alias` extends the configured `--site-hostname` primary;
  `--host-filter` explicitly supplies a replacement set (the primary
  is then NOT added). Vhost/extended/auto formats still default to
  the site hostname when neither flag is given, so foreign hosts can
  never be silently counted as this site. Both import and reprocess
  builders share the resolver; persisted aliases update only the
  `allowed_hosts` column of the already-bound source.
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

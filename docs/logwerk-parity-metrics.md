# LogWerk parity metrics (T2a slices C/D, T2b slices E/F/H) — definitions and provenance

Status: implemented 2026-11-01 on `feature/logwerk-parity-2026-11-01`
(shared service/query layer only; HTTP wiring is T3, admin UI is T4).
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

## Request journeys (slice E, PAR-05)

- Journeys are technical groupings of stored requests by
  `(client_pseudonym, sanitized User-Agent)`: a User-Agent change
  starts a new key (never a continuation), and the grouping never
  claims visitors, people, browser sessions or clicks. `journey_list`,
  `journey_timeline` and `journey_entry_paths` share the contract
  (`JourneyQuery`/`JourneyTimelineQuery`) and one SQL segmentation.
- **Boundary rule**: a new journey starts when the gap to the previous
  event of the same key **strictly exceeds 1800 seconds**; a gap of
  exactly 1800 seconds continues the journey (tested with 29m59s,
  30m00s and 30m01s gaps plus identical timestamps, which share a
  journey ordered by row id). Stable journey IDs are SHA-256 over
  site/source scope, pseudonym, sanitized agent (`None` marked, never
  colliding) and start instant.
- Boundaries derive from the site/source/window event stream BEFORE
  any content matcher: the filtered `shown` count is a conditional
  aggregate computed afterwards, so a filter hiding the first or a
  middle request shrinks `shown` but never invents a start, moves an
  entry path or changes the journey ID (tested). Entry paths always
  aggregate the base-scope first request of eligible journeys
  (`min_requests` filtered rows), with complete/partial shares.
- Window edges are honest, never widened: a first-of-key journey is
  `left_truncated` only when `start - window_from < 1800s`, a last
  journey `right_truncated` only when `window_to - end < 1800s` (at
  exactly the gap distance a hidden neighbour would start its own
  journey, so the edge is provably complete — tested both sides). No
  read outside the authorized window ever happens.
- Exact `total_groups` via grouped-subquery counts; only the requested
  page crosses into Python (never a `fetchall` of every event); list
  sorts (`requests_desc` ranks filtered shown, plus `start_asc`,
  `start_desc`, `duration_desc` with stable ID tie-breaks), `limit` /
  `offset`, and bounded timelines (`shown`/`total`/`truncated` per
  journey) with `KeyError` for unknown keys.

## Security candidates and baseline comparison (slices F/H, PAR-06)

- Security catalog `config/security_rules.yaml` v3: the three v1/v2
  rules keep IDs and version 1 byte-identical (including the
  conservative conflicting-bot-identity rule); eight original v1
  candidates cover exposed config/secrets, CMS/PHP, device/admin/proxy,
  traversal, origin-observed malformed requests (stored 400),
  401/403 challenge clusters, per-pseudonym 401/403 rates and
  sensitive-surface breadth (threshold 4). All `severity: candidate`.
- Matching runs on stored sanitized data only (query-stripped,
  secret-masked paths; stored origin statuses; HMAC pseudonyms) or the
  allowlisted pre-discard reason-code vocabulary reported at line
  level. Rejected lines never become findings: `rejected_lines`
  reports per-import line totals plus the code vocabulary, while
  status-400 rows are origin-observed events. A 401 is an
  authentication challenge and a 403 an authorization refusal — neither
  proves a failed login; a 304 stays normal cache validation.
- Totals are exact whole-scope SQL (`COUNT(*)` /
  `COUNT(DISTINCT path)` / grouped-subquery offender totals) no matter
  how many distinct paths exist (proven with 5050 rare paths beyond
  the old 5000 cap: totals exact, sample bounded with
  `shown`/`total`/`truncated`). Only samples are bounded: top
  path/status rows (`JOURNEY_SAMPLE_PATHS`), top offenders
  (`SECURITY_MAX_OFFENDERS`) with explicit truncation, bounded
  per-offender samples. The legacy 4xx rule keeps its historic
  all-status sample shape; the old capped-scan pseudo-finding is gone.
- `compare_windows` validates identical site/source scope and exactly
  equal durations (`ValueError` otherwise) and reads only the two
  windows. Each side reports coverage range, raw counts, absolute
  change and ratio/percentage per metric (requests, 4xx, 5xx, bytes,
  claimed-bot/automation requests, requests/hour). Zero baselines
  yield an exact change with `ratio: None` (`zero_baseline`, never
  infinite); running/failed imports on either side mark every ratio
  `insufficient_coverage`. `previous_window_filter` slides exactly one
  duration with selectors preserved.

## Provenance

- Enrichment policy tag `t1b.1` (plus custom fingerprints); old rows
  gain enrichment only via read-only source reprocess.
- Bot catalog: `config/bot_rules.yaml`, 77 rules (18 `ai_crawler`),
  asserted untouched by test.
- Security catalog: `config/security_rules.yaml` v3 (2026-11-01,
  parity T2b): v1/v2 rules unchanged, eight original v1 candidates;
  no LogWerk material reused; provenance string in-file.
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

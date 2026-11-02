"""Explicit OpenAPI response schemas for /api/v1 (T5).

These models are the versioned contract: every analytics response
carries site, time range, generation time, filters, coverage, quality
and warnings. No raw logs, IPs, query values, credentials or SQL ever
appear here.
"""

from pydantic import BaseModel, Field


class TimeRangeOut(BaseModel):
    time_from: str
    time_to: str


class TotalsOut(BaseModel):
    requests: int
    errors_4xx: int
    errors_5xx: int
    bytes_total: int
    bytes_measured: int


class StatusCountOut(BaseModel):
    status: int
    requests: int


class DurationOut(BaseModel):
    available: bool
    measured: int
    reason: str | None = None


class CoverageOut(BaseModel):
    unique_events: int
    observed_min: str | None = None
    observed_max: str | None = None
    sources: list[str] = Field(default_factory=list)


class ImportStateOut(BaseModel):
    import_id: int
    status: str
    error_summary: str | None = None


class QualityOut(BaseModel):
    import_attempts: dict[str, int]
    imports: list[ImportStateOut]


class SummaryResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    generated_at: str
    filters: dict[str, object]
    totals: TotalsOut
    status_distribution: list[StatusCountOut]
    duration: DurationOut
    coverage: CoverageOut
    data_quality: QualityOut
    warnings: list[str]
    limitations: list[str]


class BucketCount(BaseModel):
    bucket: str
    requests: int
    errors: int
    bytes_total: int


class TimeseriesResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    bucket: str
    buckets: list[BucketCount]
    coverage: dict[str, object]


class BotRowOut(BaseModel):
    rule_id: str
    rule_version: int
    category: str
    title: str
    meaning: str
    provider: str | None = None
    purpose: str | None = None
    traffic: str
    requests: int
    errors_4xx: int
    errors_5xx: int
    bytes_total: int
    distinct_agents: int
    distinct_paths: int


class BotTableResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    sort: str
    items: list[BotRowOut]
    total_rules: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class PathCountOut(BaseModel):
    path: str
    status: int
    requests: int


class AgentSampleOut(BaseModel):
    user_agent: str
    requests: int


class BotDetailResponse(BaseModel):
    rule_id: str
    rule_version: int
    category: str
    title: str
    meaning: str
    provider: str | None = None
    purpose: str | None = None
    traffic: str
    filters: dict[str, object]
    window: dict[str, str]
    counts: dict[str, int]
    top_paths: list[PathCountOut]
    not_found: list[PathCountOut]
    robots_requests: int
    sitemap_requests: int
    sample_agents: list[AgentSampleOut]
    coverage: dict[str, object]
    limitations: list[str]


class ExplorerRowOut(BaseModel):
    ts_utc: str
    method: str
    path: str
    status: int
    bytes: int | None = None
    referer_host: str | None = None
    user_agent: str | None = None
    ua_truncated: bool = False
    client_pseudonym: str
    traffic: str
    rule_id: str | None = None
    conflict: bool = False
    # Approved SAFE per-request enrichment (PAR-03/T3 surface).
    # Combined-only/old absent values stay null; units for timings
    # are milliseconds (see ``timing_units`` on the response).
    format_id: str | None = None
    policy_version: str | None = None
    referer_scheme: str | None = None
    referer_path: str | None = None
    server_host: str | None = None
    http_version: str | None = None
    request_time_ms: float | None = None
    upstream_time_ms: float | None = None
    upstream_count: int | None = None
    cache_status: str | None = None
    mime_type: str | None = None
    tls_protocol: str | None = None
    timing_available: bool = False
    upstream_available: bool = False


class ExplorerResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    sort: str
    items: list[ExplorerRowOut]
    total_rows: int
    limit: int
    offset: int
    timing_units: str = "milliseconds"
    coverage: dict[str, object]
    limitations: list[str]


class ResourceKindOut(BaseModel):
    kind: str
    requests: int
    errors: int
    bytes_total: int


class ResourceBreakdownResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    items: list[ResourceKindOut]
    coverage: dict[str, object]
    limitations: list[str]


class BrowserShareOut(BaseModel):
    family: str
    requests: int


class OsShareOut(BaseModel):
    os: str
    requests: int


class BrowserBreakdownResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    families: list[BrowserShareOut]
    systems: list[OsShareOut]
    coverage: dict[str, object]
    limitations: list[str]


class HeatmapResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    timezone: str
    matrix: list[list[int]]
    utc_buckets: int
    dst_merges: int
    coverage: dict[str, object]
    limitations: list[str]


class ClientRowOut(BaseModel):
    client_pseudonym: str
    requests: int
    errors: int
    paths: int
    first_seen: str | None = None
    last_seen: str | None = None


class ClientTopResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    items: list[ClientRowOut]
    total_clients: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class PathItemOut(BaseModel):
    path: str
    method: str
    requests: int
    errors: int
    bytes_total: int


class TrafficBucketOut(BaseModel):
    traffic: str
    requests: int
    errors_4xx: int
    errors_5xx: int
    bytes_total: int


class TrafficBreakdownResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    buckets: list[TrafficBucketOut]
    coverage: dict[str, object]
    limitations: list[str]


class TopPathsResponse(BaseModel):
    items: list[PathItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]


class ReferrerItemOut(BaseModel):
    referer_host: str
    requests: int
    paths: int


class TopReferrersResponse(BaseModel):
    items: list[ReferrerItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]


class ErrorGroupOut(BaseModel):
    path: str
    status: int
    requests: int
    referrers: int


class ErrorsResponse(BaseModel):
    items: list[ErrorGroupOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]


class FindingOut(BaseModel):
    rule_id: str
    rule_version: int
    category: str
    title: str
    severity: str
    meaning: str
    window: dict[str, str]
    filters: dict[str, object]
    observation_time: str
    counts: dict[str, int]
    evidence: dict[str, object]
    coverage_summary: dict[str, object]
    limitations: list[str]


class FindingsResponse(BaseModel):
    items: list[FindingOut]
    total: int
    coverage: dict[str, object]


class PerformanceResponse(BaseModel):
    available: bool
    measured: int
    reason: str | None = None


class TimingStatsOut(BaseModel):
    measured: int
    missing: int
    total: int
    coverage: float | None = None
    min_ms: float | None = None
    max_ms: float | None = None
    average_ms: float | None = None
    median_ms: float | None = None
    p50_ms: float | None = None
    p95_ms: float | None = None
    p99_ms: float | None = None
    warnings: list[str] = Field(default_factory=list)


class DistributionItemOut(BaseModel):
    value: str
    requests: int


class DistributionPageOut(BaseModel):
    shown: int
    total_values: int
    known_values: int
    unknown_requests: int
    other_requests: int
    truncated: bool
    limit: int
    offset: int


class DistributionOut(BaseModel):
    items: list[DistributionItemOut]
    total: int
    shown: int
    total_values: int
    known_values: int
    unknown_requests: int
    other_requests: int
    truncated: bool
    limit: int
    offset: int


class PerformanceOverviewResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    generated_at: str
    filters: dict[str, object]
    latency_available: bool
    latency_ms: TimingStatsOut
    upstream_ms: TimingStatsOut
    units: str = "milliseconds"
    percentile_definition: str
    cache: dict[str, object]
    mime_vs_resource: dict[str, object]
    http_versions: dict[str, object]
    tls_protocols: dict[str, object]
    logged_hosts: dict[str, object]
    coverage: dict[str, object]
    warnings: list[str]
    limitations: list[str]


class SlowEndpointItemOut(BaseModel):
    path: str
    measured: int
    min_ms: float | None = None
    max_ms: float | None = None
    average_ms: float | None = None
    p50_ms: float | None = None
    p95_ms: float | None = None


class SlowEndpointsResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    sort: str
    items: list[SlowEndpointItemOut]
    total_paths: int
    meta: dict[str, object]
    limit: int
    offset: int
    units: str = "milliseconds"
    coverage: dict[str, object]
    limitations: list[str]


class SeoStatusItemOut(BaseModel):
    path: str
    status_class: str
    rule_id: str | None = None
    category: str | None = None
    provider: str | None = None
    purpose: str | None = None
    requests: int
    bytes_total: int
    drilldown: dict[str, object]


class SeoStatusResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    status_class: str
    items: list[SeoStatusItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class AiOnlyPathItemOut(BaseModel):
    path: str
    ai_requests: int
    ai_bytes: int
    rules: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    drilldown: dict[str, object]


class AiOnlyPathsResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    generated_at: str
    filters: dict[str, object]
    items: list[AiOnlyPathItemOut]
    total_paths: int
    comparison: dict[str, object]
    candidate: dict[str, object]
    coverage: dict[str, object]
    vacuous: bool
    warnings: list[str]
    limit: int
    offset: int
    limitations: list[str]


class Referrer404ItemOut(BaseModel):
    referer_host: str
    referer_scheme: str | None = None
    referer_path: str | None = None
    target_path: str
    requests: int
    internal: bool


class Referrer404Response(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    own_hosts: list[str]
    relation: str
    host_matching: str
    items: list[Referrer404ItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class ReferrerUrlItemOut(BaseModel):
    referer_host: str
    referer_scheme: str | None = None
    referer_path: str | None = None
    requests: int
    errors: int
    bytes_total: int | None = None
    bytes_known: int
    internal: bool


class ReferrerUrlsResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    own_hosts: list[str]
    relation: str
    host_matching: str
    items: list[ReferrerUrlItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class JourneyItemOut(BaseModel):
    journey_id: str
    client_pseudonym: str
    requests_total: int
    requests_shown: int
    started_at: str
    ended_at: str
    #: Elapsed float seconds plus the exact integer-microsecond
    #: companion (same epoch-micros arithmetic as grouping/sort).
    duration_s: float
    duration_us: int
    entry_path: str
    left_truncated: bool
    right_truncated: bool
    completeness: str


class JourneysResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    generated_at: str
    filters: dict[str, object]
    gap_definition: str
    sort: str
    min_requests: int
    items: list[JourneyItemOut]
    total_groups: int
    limit: int
    offset: int
    coverage: dict[str, object]
    limitations: list[str]


class JourneyTimelineItemOut(BaseModel):
    ts_utc: str
    method: str
    path: str
    status: int
    bytes: int | None = None
    referer_host: str | None = None
    user_agent: str | None = None
    ua_truncated: bool = False


class JourneyTimelineResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    journey_id: str
    client_pseudonym: str
    started_at: str
    ended_at: str
    requests_total: int
    requests_shown: int
    entry_path: str
    left_truncated: bool
    right_truncated: bool
    items: list[JourneyTimelineItemOut]
    shown: int
    total: int
    truncated: bool
    limit: int
    offset: int
    resolved_via: str | None = None
    coverage: dict[str, object]
    limitations: list[str]


class JourneyEntryItemOut(BaseModel):
    entry_path: str
    journeys: int
    complete_journeys: int
    partial_journeys: int


class JourneyEntryPathsResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    generated_at: str
    filters: dict[str, object]
    min_requests: int
    items: list[JourneyEntryItemOut]
    total_groups: int
    limit: int
    offset: int
    partial_caveat: str
    coverage: dict[str, object]
    limitations: list[str]


class ComparisonMetricOut(BaseModel):
    #: Raw integer metrics (request/error/byte counts) travel as
    #: integers end to end — never through a lossy ``float`` — so
    #: values above 2**53 stay exact. Rates (``requests_per_hour``)
    #: are floats by nature. Ratios stay finite optional floats.
    name: str
    current: int | float
    previous: int | float
    absolute_change: int | float
    ratio: float | None = None
    percent: float | None = None
    ratio_status: str
    note: str


class ComparisonResponse(BaseModel):
    site_id: str
    source_id: str | None = None
    current_window: TimeRangeOut
    previous_window: TimeRangeOut
    selectors: dict[str, object]
    filters: dict[str, object]
    #: Shared window length: float seconds plus the exact
    #: integer-microsecond companion, consistent with the ISO pair.
    window_seconds: float
    window_seconds_us: int
    generated_at: str
    metrics: list[ComparisonMetricOut]
    coverage: dict[str, object]
    comparable: bool
    comparable_reasons: list[str]
    limitations: list[str]


class LoginResponse(BaseModel):
    username: str
    csrf_token: str
    expires_at: str


class TokenIssueResponse(BaseModel):
    token_id: int
    token: str
    name: str
    site_id: str
    scopes: str
    expires_at: str | None = None


class TokenMetaOut(BaseModel):
    id: int
    name: str
    site_id: str
    scopes: str
    created_at: str
    expires_at: str | None = None
    revoked_at: str | None = None


class ReadyResponse(BaseModel):
    ready: bool
    database: str
    schema_version: int | None = None

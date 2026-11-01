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
    client_pseudonym: str
    traffic: str
    rule_id: str | None = None


class ExplorerResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    filters: dict[str, object]
    sort: str
    items: list[ExplorerRowOut]
    total_rows: int
    limit: int
    offset: int
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

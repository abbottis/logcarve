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


class BucketOut(BaseModel):
    bucket: str
    requests: int
    errors: int


class TimeseriesResponse(BaseModel):
    site_id: str
    time_range: TimeRangeOut
    bucket: str
    buckets: list[BucketOut]
    coverage: dict[str, object]


class PathItemOut(BaseModel):
    path: str
    method: str
    requests: int
    errors: int


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

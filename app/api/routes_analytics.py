"""Read-only /api/v1 analytics endpoints (T5).

Every request needs a Bearer token with ``analytics:read``; the token's
bound site and scope are enforced server-side on each call. Responses are
the shared deterministic analytics plus envelope metadata. Analytics
tokens authorize nothing else: no imports, sessions, chat or models.
"""

from dataclasses import asdict
from datetime import datetime
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.analytics import service
from app.analytics.classification import build_classifier, resolve_selector_indexes
from app.analytics.contracts import (
    AnalyticsFilter,
    BotTableQuery,
    ExplorerQuery,
    JourneyIdQuery,
    JourneyQuery,
    JourneyTimelineQuery,
    SlowEndpointsQuery,
    TimeWindow,
    TopPathsQuery,
    TopReferrersQuery,
)
from app.api import schemas
from app.api.deps import (
    read_store,
    require_analytics_token,
    require_token_site,
    require_token_source,
)
from app.api.errors import error_response

router = APIRouter(prefix="/api/v1")

SiteId = Annotated[str, Query(min_length=1, max_length=128)]
TimeFrom = Annotated[datetime, Query(alias="from")]
TimeTo = Annotated[datetime, Query(alias="to")]
SourceId = Annotated[str | None, Query(min_length=1, max_length=128)]
Method = Annotated[str | None, Query(min_length=1, max_length=32)]
Status = Annotated[int | None, Query(ge=100, le=599)]
PathPrefix = Annotated[str | None, Query(min_length=1, max_length=1024)]
PathExact = Annotated[str | None, Query(min_length=1, max_length=1024)]
RefererHost = Annotated[str | None, Query(min_length=1, max_length=253)]
Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0, le=2**63 - 1)]
Timezone = Annotated[str, Query(min_length=1, max_length=64)]
ServerHost = Annotated[str | None, Query(min_length=1, max_length=253)]
HttpVersion = Annotated[str | None, Query(min_length=1, max_length=16)]
MimeType = Annotated[str | None, Query(min_length=1, max_length=128)]
CacheStatus = Annotated[str | None, Query(min_length=1, max_length=32)]
TlsProtocol = Annotated[str | None, Query(min_length=1, max_length=32)]
TimingAvailable = Annotated[bool | None, Query()]
UpstreamAvailable = Annotated[bool | None, Query()]
TimingMin = Annotated[float | None, Query(ge=0)]
TimingMax = Annotated[float | None, Query(ge=0)]
TrafficParam = Annotated[
    Literal["all", "browser_like", "claimed_bot", "other_automation", "unknown"], Query()
]
#: T5a offline-country selector (PAR-09): ISO 3166-1 alpha-2 (any
#: case, stored uppercase) or the explicit ``UNKNOWN`` selector for
#: rows with no known country. The shared contract validates and
#: normalizes; anything else (including blank, which ``min_length``
#: already rejects) answers 400.
CountryParam = Annotated[str | None, Query(min_length=1, max_length=16)]
StatusClassParam = Annotated[Literal["2xx", "3xx", "4xx", "5xx"] | None, Query()]
SearchParam = Annotated[str | None, Query(min_length=1, max_length=128)]
ClientParam = Annotated[str | None, Query(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]
BotParam = Annotated[str | None, Query(min_length=1, max_length=64)]
CategoryParam = Annotated[str | None, Query(min_length=1, max_length=64)]
ProviderParam = Annotated[str | None, Query(min_length=1, max_length=120)]
PurposeParam = Annotated[str | None, Query(min_length=1, max_length=120)]
HeatmapTz = Annotated[str, Query(min_length=1, max_length=64)]


def _deny(request_id: str, code: str, message: str, status: int = 400):
    return error_response(status, code, message, request_id)


def _prepare(
    request: Request,
    *,
    site_id: str,
    time_from: datetime,
    time_to: datetime,
    source_id: str | None,
    method: str | None,
    status: int | None,
    status_class: str | None,
    path_prefix: str | None,
    path_exact: str | None,
    referer_host: str | None,
    search: str | None,
    client: str | None,
    traffic: str,
    bot: str | None,
    category: str | None,
    provider: str | None,
    purpose: str | None,
    server_host: str | None,
    http_version: str | None,
    mime_type: str | None,
    cache_status: str | None,
    tls_protocol: str | None,
    timing_available: bool | None,
    upstream_available: bool | None,
    timing_min_ms: float | None,
    timing_max_ms: float | None,
    country: str | None,
    limit: int,
    offset: int,
    timezone: str,
):
    token = require_analytics_token(request)
    if isinstance(token, JSONResponse):
        return None, None, token
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return None, None, _deny(request.state.request_id, "invalid_request", "Unknown timezone.")
    if timezone != "UTC":
        return (
            None,
            None,
            _deny(
                request.state.request_id,
                "unsupported_timezone",
                "Only UTC is supported in this version.",
            ),
        )
    try:
        filt = AnalyticsFilter(
            site_id=site_id,
            source_id=source_id,
            window=TimeWindow(time_from=time_from, time_to=time_to),
            method=method,
            status=status,
            status_class=status_class,  # type: ignore[arg-type]
            path_prefix=path_prefix,
            path_exact=path_exact,
            referer_host=referer_host,
            search=search,
            client=client,
            traffic=traffic,  # type: ignore[arg-type]
            bot=bot,
            category=category,
            provider=provider,
            purpose=purpose,
            server_host=server_host,
            http_version=http_version,
            mime_type=mime_type,
            cache_status=cache_status,
            tls_protocol=tls_protocol,
            timing_available=timing_available,
            upstream_available=upstream_available,
            timing_min_ms=timing_min_ms,
            timing_max_ms=timing_max_ms,
            country=country,
            limit=limit,
            offset=offset,
        )
    except ValidationError:
        return (
            None,
            None,
            _deny(request.state.request_id, "invalid_request", "Request validation failed."),
        )
    try:
        clf = build_classifier(list(request.app.state.rules))
        resolve_selector_indexes(
            clf,
            bot=filt.bot,
            category=filt.category,
            provider=filt.provider,
            purpose=filt.purpose,
        )
    except ValueError:
        return (
            None,
            None,
            _deny(
                request.state.request_id,
                "invalid_request",
                "Unknown or contradictory traffic/bot selector.",
            ),
        )
    denied = require_token_site(token, filt.site_id, request.state.request_id)
    if denied is not None:
        return None, None, denied
    if filt.source_id is not None:
        with read_store(request) as conn:
            denied = require_token_source(
                conn, token=token, source_id=filt.source_id, request_id=request.state.request_id
            )
        if denied is not None:
            return None, None, denied
    return token, filt, None


def _params(
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
) -> dict:
    return {
        "site_id": site_id,
        "time_from": time_from,
        "time_to": time_to,
        "source_id": source_id,
        "method": method,
        "status": status,
        "status_class": status_class,
        "path_prefix": path_prefix,
        "referer_host": referer_host,
        "search": search,
        "client": client,
        "traffic": traffic,
        "bot": bot,
        "category": category,
        "provider": provider,
        "purpose": purpose,
        "path_exact": path_exact,
        "server_host": server_host,
        "http_version": http_version,
        "mime_type": mime_type,
        "cache_status": cache_status,
        "tls_protocol": tls_protocol,
        "timing_available": timing_available,
        "upstream_available": upstream_available,
        "timing_min_ms": timing_min_ms,
        "timing_max_ms": timing_max_ms,
        "country": country,
        "limit": limit,
        "offset": offset,
        "timezone": timezone,
    }


@router.get("/summary", response_model=schemas.SummaryResponse)
def get_summary(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.summarize(conn, filt, request.app.state.rules)


@router.get("/traffic/timeseries", response_model=schemas.TimeseriesResponse)
def get_timeseries(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    bucket: Annotated[Literal["hour", "day"], Query()] = "hour",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.timeseries(conn, filt, bucket, request.app.state.rules)


@router.get("/crawlers", response_model=schemas.FindingsResponse)
def get_crawlers(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        findings = service.crawler_claims(conn, filt, request.app.state.rules)
        return {
            "items": [asdict(f) for f in findings],
            "total": len(findings),
            "coverage": service.coverage_summary(conn, filt, request.app.state.rules),
        }


@router.get("/errors", response_model=schemas.ErrorsResponse)
def get_errors(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        result = service.error_groups(conn, filt, request.app.state.rules)
        items, total = result["items"], result["total_groups"]
        return {
            "items": items,
            "total_groups": total,
            "limit": filt.limit,
            "offset": filt.offset,
            "coverage": service.coverage_summary(conn, filt, request.app.state.rules),
        }


@router.get("/paths", response_model=schemas.TopPathsResponse)
def get_paths(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[
        Literal["requests_desc", "errors_desc", "bytes_desc"], Query()
    ] = "requests_desc",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        result = service.top_paths(
            conn, TopPathsQuery(filt=filt, sort=sort), request.app.state.rules
        )
        return result


@router.get("/referrers", response_model=schemas.TopReferrersResponse)
def get_referrers(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.top_referrers(conn, TopReferrersQuery(filt=filt), request.app.state.rules)


@router.get("/security/findings", response_model=schemas.FindingsResponse)
def get_findings(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        findings = service.security_findings(conn, filt, request.app.state.rules)
        return {
            "items": [asdict(f) for f in findings],
            "total": len(findings),
            "coverage": service.coverage_summary(conn, filt, request.app.state.rules),
        }


@router.get("/performance", response_model=schemas.PerformanceResponse)
def get_performance(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.summarize(conn, filt, request.app.state.rules)["duration"]


@router.get("/traffic/breakdown", response_model=schemas.TrafficBreakdownResponse)
def get_traffic_breakdown(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.traffic_breakdown(conn, filt, request.app.state.rules)


@router.get("/countries", response_model=schemas.CountryBreakdownResponse)
def get_countries(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.country_breakdown(conn, filt, request.app.state.rules)


@router.get("/traffic/resources", response_model=schemas.ResourceBreakdownResponse)
def get_traffic_resources(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.resource_breakdown(conn, filt, request.app.state.rules)


@router.get("/traffic/browsers", response_model=schemas.BrowserBreakdownResponse)
def get_traffic_browsers(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.browser_breakdown(conn, filt, request.app.state.rules)


@router.get("/traffic/heatmap", response_model=schemas.HeatmapResponse)
def get_traffic_heatmap(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    tz: HeatmapTz = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.heatmap(conn, filt, request.app.state.rules, tz_name=tz)
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown timezone.")


@router.get("/traffic/clients", response_model=schemas.ClientTopResponse)
def get_traffic_clients(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.client_top(conn, filt, request.app.state.rules)


@router.get("/bots", response_model=schemas.BotTableResponse)
def get_bots(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[
        Literal["requests_desc", "name_asc", "category_asc", "errors_desc", "bytes_desc"],
        Query(),
    ] = "requests_desc",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.bot_table(conn, BotTableQuery(filt=filt, sort=sort), request.app.state.rules)


@router.get("/bots/{rule_id}", response_model=schemas.BotDetailResponse)
def get_bot_detail(
    request: Request,
    rule_id: str,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.bot_detail(conn, filt, request.app.state.rules, rule_id)
        except KeyError:
            return _deny(request.state.request_id, "unknown_bot", "Unknown bot rule.", 404)
        except ValueError:
            return _deny(
                request.state.request_id,
                "invalid_request",
                "Contradictory traffic/bot selector.",
            )


@router.get("/requests", response_model=schemas.ExplorerResponse)
def get_requests(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[
        Literal[
            "newest",
            "oldest",
            "time_asc",
            "time_desc",
            "client_asc",
            "client_desc",
            "method_asc",
            "method_desc",
            "path_asc",
            "path_desc",
            "status_asc",
            "status_desc",
            "bytes_asc",
            "bytes_desc",
        ],
        Query(),
    ] = "newest",
):
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.request_explorer(
            conn, ExplorerQuery(filt=filt, sort=sort), request.app.state.rules
        )


@router.get("/performance/overview", response_model=schemas.PerformanceOverviewResponse)
def get_performance_overview(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    """Measured latency/upstream/cache/MIME/version/TLS/host distributions."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.performance_overview(conn, filt, request.app.state.rules)


@router.get("/performance/slow-endpoints", response_model=schemas.SlowEndpointsResponse)
def get_slow_endpoints(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[
        Literal["avg_desc", "p95_desc", "requests_desc", "max_desc"], Query()
    ] = "avg_desc",
):
    """Slow measured endpoints with exact per-path percentiles (milliseconds)."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    try:
        query = SlowEndpointsQuery(filt=filt, sort=sort)
    except ValidationError:
        return _deny(request.state.request_id, "invalid_request", "Request validation failed.")
    with read_store(request) as conn:
        try:
            return service.slow_endpoints(conn, query, request.app.state.rules)
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown sort.")


@router.get("/seo/bot-statuses", response_model=schemas.SeoStatusResponse)
def get_seo_bot_statuses(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    report: Annotated[Literal["3xx", "4xx", "5xx"], Query()] = "4xx",
):
    """Claimed-bot redirects/client/server errors grouped by path and rule."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.seo_status_groups(
                conn, filt, request.app.state.rules, status_class=report
            )
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown status class.")


@router.get("/seo/ai-only-paths", response_model=schemas.AiOnlyPathsResponse)
def get_seo_ai_only_paths(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    """Paths observed only for the selected AI candidates, with caveats."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.ai_only_paths(conn, filt, request.app.state.rules)
        except ValueError:
            return _deny(
                request.state.request_id,
                "invalid_request",
                "Selectors cannot hold AI-candidate rows.",
            )


@router.get("/referrers/urls", response_model=schemas.ReferrerUrlsResponse)
def get_referrer_urls(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    relation: Annotated[Literal["all", "internal", "external"], Query()] = "all",
):
    """All sanitized referrer source URLs (LogWerk renderRefererUrls).

    Every stored referrer contributes regardless of status; the
    404-only report stays at ``/referrers/404-targets``. Grouping,
    internal labelling, totals, paging and filter scopes mirror the
    404 report. Missing scheme/path renders as Unknown, never as an
    invented URL or direct-traffic claim.
    """
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.referrer_urls(conn, filt, request.app.state.rules, relation=relation)  # type: ignore[arg-type]
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown relation.")


@router.get("/referrers/404-targets", response_model=schemas.Referrer404Response)
def get_referrer_404_targets(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    relation: Annotated[Literal["all", "internal", "external"], Query()] = "all",
):
    """Referrer-path to target-404 report over sanitized fields."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.referrer_404s(conn, filt, request.app.state.rules, relation=relation)  # type: ignore[arg-type]
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown relation.")


@router.get("/journeys", response_model=schemas.JourneysResponse)
def get_journeys(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[
        Literal["requests_desc", "start_asc", "start_desc", "duration_desc"], Query()
    ] = "requests_desc",
    min_requests: Annotated[int, Query(ge=1, le=1000)] = 1,
):
    """Paginated technical request journeys (never visitors or sessions)."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    try:
        query = JourneyQuery(filt=filt, sort=sort, min_requests=min_requests)  # type: ignore[arg-type]
    except ValidationError:
        return _deny(request.state.request_id, "invalid_request", "Request validation failed.")
    with read_store(request) as conn:
        try:
            return service.journeys(conn, query, request.app.state.rules)
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Unknown sort.")


@router.get("/journeys/entry-paths", response_model=schemas.JourneyEntryPathsResponse)
def get_journey_entry_paths(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    min_requests: Annotated[int, Query(ge=1, le=1000)] = 1,
):
    """Entry-path aggregation from eligible complete/partial journeys."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        try:
            return service.journey_entry_paths(
                conn, filt, request.app.state.rules, min_requests=min_requests
            )
        except ValueError:
            return _deny(request.state.request_id, "invalid_request", "Request validation failed.")


@router.get("/journeys/timeline", response_model=schemas.JourneyTimelineResponse)
def get_journey_timeline(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    client_pseudonym: Annotated[str, Query(min_length=1, max_length=128)],
    journey_start: Annotated[datetime, Query()],
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    user_agent: Annotated[str | None, Query(max_length=4096)] = None,
):
    """Bounded chronological timeline for one journey key in scope."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    try:
        query = JourneyTimelineQuery(
            filt=filt,
            client_pseudonym=client_pseudonym,
            user_agent=user_agent,
            journey_start=journey_start,
        )
    except ValidationError:
        return _deny(request.state.request_id, "invalid_request", "Request validation failed.")
    with read_store(request) as conn:
        try:
            return service.journey_timeline(conn, query, request.app.state.rules)
        except KeyError:
            return _deny(request.state.request_id, "unknown_journey", "Unknown journey.", 404)
        except ValueError:
            return _deny(
                request.state.request_id,
                "invalid_request",
                "Contradictory traffic/bot selector.",
            )


@router.get("/journeys/by-id", response_model=schemas.JourneyTimelineResponse)
def get_journey_timeline_by_id(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    client_pseudonym: Annotated[str, Query(min_length=1, max_length=128)],
    journey_start: Annotated[datetime, Query()],
    journey_id: Annotated[str, Query(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")],
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    """Bounded timeline for one opaque journey ID listed by ``GET /journeys``."""
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    try:
        query = JourneyIdQuery(
            filt=filt,
            client_pseudonym=client_pseudonym,
            journey_start=journey_start,
            journey_id=journey_id,
        )
    except ValidationError:
        return _deny(request.state.request_id, "invalid_request", "Request validation failed.")
    with read_store(request) as conn:
        try:
            return service.journey_timeline_by_id(conn, query, request.app.state.rules)
        except KeyError:
            return _deny(request.state.request_id, "unknown_journey", "Unknown journey.", 404)
        except ValueError:
            return _deny(
                request.state.request_id,
                "invalid_request",
                "Contradictory traffic/bot selector.",
            )


@router.get("/comparison", response_model=schemas.ComparisonResponse)
def get_comparison(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    baseline_from: Annotated[datetime, Query()],
    baseline_to: Annotated[datetime, Query()],
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    status_class: StatusClassParam = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    search: SearchParam = None,
    client: ClientParam = None,
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
    path_exact: PathExact = None,
    server_host: ServerHost = None,
    http_version: HttpVersion = None,
    mime_type: MimeType = None,
    cache_status: CacheStatus = None,
    tls_protocol: TlsProtocol = None,
    timing_available: TimingAvailable = None,
    upstream_available: UpstreamAvailable = None,
    timing_min_ms: TimingMin = None,
    timing_max_ms: TimingMax = None,
    country: CountryParam = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
):
    """Current-vs-baseline comparison over two validated equal-length windows.

    Both windows share the token's site/source scope and identical
    selectors; only the validated windows may differ. No hidden
    history widening: the baseline travels the same site/source and
    window-length contract as any other query.
    """
    _, filt, err = _prepare(
        request,
        **_params(
            site_id,
            time_from,
            time_to,
            source_id,
            method,
            status,
            status_class,
            path_prefix,
            referer_host,
            search,
            client,
            traffic,
            bot,
            category,
            provider,
            purpose,
            path_exact,
            server_host,
            http_version,
            mime_type,
            cache_status,
            tls_protocol,
            timing_available,
            upstream_available,
            timing_min_ms,
            timing_max_ms,
            country,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    try:
        previous = filt.model_copy(
            update={"window": TimeWindow(time_from=baseline_from, time_to=baseline_to)}
        )
    except ValidationError:
        return _deny(request.state.request_id, "invalid_request", "Request validation failed.")
    with read_store(request) as conn:
        try:
            return service.compare_windows(conn, filt, previous, request.app.state.rules)
        except ValueError:
            return _deny(
                request.state.request_id,
                "invalid_request",
                "Comparison windows must share scope, length and selectors.",
            )


@router.get("/openapi.json")
def get_openapi(request: Request):
    token = require_analytics_token(request)
    if isinstance(token, JSONResponse):
        return token
    return request.app.openapi()

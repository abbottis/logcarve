"""Read-only /api/v1 analytics endpoints (T5).

Every request needs a Bearer [REDACTED] with ``analytics:read``; the token's
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
RefererHost = Annotated[str | None, Query(min_length=1, max_length=253)]
Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]
Timezone = Annotated[str, Query(min_length=1, max_length=64)]
TrafficParam = Annotated[
    Literal["all", "browser_like", "claimed_bot", "other_automation", "unknown"], Query()
]
StatusClassParam = Annotated[Literal["2xx", "3xx", "4xx", "5xx"] | None, Query()]
SearchParam = Annotated[str | None, Query(min_length=1, max_length=128)]
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
    referer_host: str | None,
    search: str | None,
    traffic: str,
    bot: str | None,
    category: str | None,
    provider: str | None,
    purpose: str | None,
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
            referer_host=referer_host,
            search=search,
            traffic=traffic,  # type: ignore[arg-type]
            bot=bot,
            category=category,
            provider=provider,
            purpose=purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
        "traffic": traffic,
        "bot": bot,
        "category": category,
        "provider": provider,
        "purpose": purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.traffic_breakdown(conn, filt, request.app.state.rules)


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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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
    traffic: TrafficParam = "all",
    bot: BotParam = None,
    category: CategoryParam = None,
    provider: ProviderParam = None,
    purpose: PurposeParam = None,
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
            traffic,
            bot,
            category,
            provider,
            purpose,
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


@router.get("/openapi.json")
def get_openapi(request: Request):
    token = require_analytics_token(request)
    if isinstance(token, JSONResponse):
        return token
    return request.app.openapi()

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

from app.analytics import queries, service
from app.analytics.contracts import AnalyticsFilter, TimeWindow, TopPathsQuery, TopReferrersQuery
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
    path_prefix: str | None,
    referer_host: str | None,
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
            path_prefix=path_prefix,
            referer_host=referer_host,
            limit=limit,
            offset=offset,
        )
    except ValidationError:
        return (
            None,
            None,
            _deny(request.state.request_id, "invalid_request", "Request validation failed."),
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
        "path_prefix": path_prefix,
        "referer_host": referer_host,
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.summarize(conn, filt)


@router.get("/traffic/timeseries", response_model=schemas.TimeseriesResponse)
def get_timeseries(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.timeseries(conn, filt, bucket)


@router.get("/crawlers", response_model=schemas.FindingsResponse)
def get_crawlers(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
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
            "coverage": service.coverage_summary(conn, filt),
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        items, total = queries.error_groups(conn, filt)
        return {
            "items": items,
            "total_groups": total,
            "limit": filt.limit,
            "offset": filt.offset,
            "coverage": service.coverage_summary(conn, filt),
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
    limit: Limit = 100,
    offset: Offset = 0,
    timezone: Timezone = "UTC",
    sort: Annotated[Literal["requests_desc", "errors_desc"], Query()] = "requests_desc",
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        result = service.top_paths(conn, TopPathsQuery(filt=filt, sort=sort))
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.top_referrers(conn, TopReferrersQuery(filt=filt))


@router.get("/security/findings", response_model=schemas.FindingsResponse)
def get_findings(
    request: Request,
    site_id: SiteId,
    time_from: TimeFrom,
    time_to: TimeTo,
    source_id: SourceId = None,
    method: Method = None,
    status: Status = None,
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
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
            "coverage": service.coverage_summary(conn, filt),
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
    path_prefix: PathPrefix = None,
    referer_host: RefererHost = None,
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
            path_prefix,
            referer_host,
            limit,
            offset,
            timezone,
        ),
    )
    if err is not None:
        return err
    with read_store(request) as conn:
        return service.summarize(conn, filt)["duration"]


@router.get("/openapi.json")
def get_openapi(request: Request):
    token = require_analytics_token(request)
    if isinstance(token, JSONResponse):
        return token
    return request.app.openapi()

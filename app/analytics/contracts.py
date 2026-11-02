"""Validated, bounded analytics contracts (T4).

One transport-independent filter/sort/pagination model for the future
dashboard, REST API and internal assistant consumers. All consumers
share these contracts, so equal filters always mean equal results.
Timestamps are UTC; naive datetimes are rejected rather than guessed.
Sort orders are allowlisted literals, never interpolated client input.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.ingestion.geoip import normalize_country_selector

MAX_LIMIT = 1000
MAX_WINDOW_DAYS = 366
MAX_SEARCH_LEN = 128
#: Largest pageable offset: the SQLite signed-64-bit binding range.
#: Larger offsets reject as invalid instead of surfacing an
#: ``OverflowError``/plain-500 from the driver.
SQLITE_INT64_MAX = 2**63 - 1
BucketSize = Literal["hour", "day"]
TopPathSort = Literal["requests_desc", "errors_desc", "bytes_desc"]
TopReferrerSort = Literal["requests_desc"]
TrafficFilter = Literal["all", "browser_like", "claimed_bot", "other_automation", "unknown"]
StatusClass = Literal["2xx", "3xx", "4xx", "5xx"]
BotTableSort = Literal["requests_desc", "name_asc", "category_asc", "errors_desc", "bytes_desc"]
#: Request explorer sorts. ``newest``/``oldest`` are the legacy time sorts
#: (kept stable: time DESC/ASC with id ties); the explicit ``time_*``
#: pair spells the same orders. Every other pair sorts one data column
#: ascending/descending with timestamp/id tie-breaks; byte sorts order
#: NULLs last and compare numeric values, never formatted strings.
ExplorerSort = Literal[
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
]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must carry a timezone")
    return value.astimezone(UTC)


class TimeWindow(BaseModel):
    """Half-open UTC window ``[time_from, time_to)``."""

    time_from: datetime
    time_to: datetime

    @field_validator("time_from", "time_to")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @model_validator(mode="after")
    def _ordered_and_bounded(self) -> "TimeWindow":
        if self.time_from >= self.time_to:
            raise ValueError("time_from must be before time_to")
        # Compare the exact duration: .days floors, which would admit up
        # to almost 24h past the bound for non-midnight-aligned windows.
        if (self.time_to - self.time_from) > timedelta(days=MAX_WINDOW_DAYS):
            raise ValueError(f"window must not exceed {MAX_WINDOW_DAYS} days")
        return self


class AnalyticsFilter(BaseModel):
    """Shared filter contract: site, optional source, UTC window, matchers, paging."""

    site_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    window: TimeWindow
    method: str | None = Field(default=None, min_length=1, max_length=32)
    status: int | None = Field(default=None, ge=100, le=599)
    status_class: StatusClass | None = Field(default=None)
    path_prefix: str | None = Field(default=None, min_length=1, max_length=1024)
    #: Exact-path selector for drilldowns that reproduce ONE stored path
    #: group (SEO/AI evidence). Unlike ``path_prefix`` (a widening
    #: ``LIKE`` exploration that also matches ``/path-extra`` and
    #: ``/path/child``), this is an equality match carried through every
    #: shared consumer so evidence filters agree with the reported row.
    #: Legacy prefix exploration remains available; prefer this selector
    #: for subsequent consumers.
    path_exact: str | None = Field(default=None, min_length=1, max_length=1024)
    referer_host: str | None = Field(default=None, min_length=1, max_length=253)
    search: str | None = Field(default=None, min_length=1, max_length=MAX_SEARCH_LEN)
    #: Exact client selector: equality on ONE stable HMAC pseudonym
    #: (64 lowercase hex), never an original address. Unlike ``search``
    #: (a widening ``LIKE`` that also matches path, User-Agent and
    #: referrer host), this matches exactly one pseudonym and intersects
    #: with every other matcher, including ``search`` itself. Unknown
    #: pseudonyms yield zero rows, never fuzzy neighbours. Trusted
    #: callers (exact-IP lookup, pinned client drilldowns) set this;
    #: the model transport can inherit it from the trusted scope but
    #: can never widen it, and it never reaches URLs carrying originals
    #: (only the HMAC travels) or any original-IP permission change.
    client: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    traffic: TrafficFilter = "all"
    bot: str | None = Field(default=None, min_length=1, max_length=64)
    category: str | None = Field(default=None, min_length=1, max_length=64)
    provider: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: str | None = Field(default=None, min_length=1, max_length=120)
    #: T2a measured-enrichment matchers (PAR-03). All optional so legacy
    #: callers stay compatible; every value is normalized and bounded
    #: here, then bound as a parameter (never interpolated) in queries.
    server_host: str | None = Field(default=None, min_length=1, max_length=253)
    http_version: str | None = Field(default=None, min_length=1, max_length=16)
    mime_type: str | None = Field(default=None, min_length=1, max_length=128)
    cache_status: str | None = Field(default=None, min_length=1, max_length=32)
    tls_protocol: str | None = Field(default=None, min_length=1, max_length=32)
    timing_available: bool | None = Field(default=None)
    upstream_available: bool | None = Field(default=None)
    timing_min_ms: float | None = Field(default=None, ge=0)
    timing_max_ms: float | None = Field(default=None, ge=0)
    #: T5a offline-country selector (PAR-09). An ISO 3166-1 alpha-2
    #: code matches looked-up rows exactly; the explicit ``UNKNOWN``
    #: selector matches rows with no known country (NULL code,
    #: including never-looked-up legacy rows). An empty value never
    #: reaches this contract (transports map it to no filter or
    #: reject); only the validated selector selects Unknown, never a
    #: silently ignored blank.
    country: str | None = Field(default=None, min_length=1, max_length=16)
    limit: int = Field(default=100, ge=1, le=MAX_LIMIT)
    offset: int = Field(default=0, ge=0, le=SQLITE_INT64_MAX)

    @field_validator("server_host", "http_version", "mime_type", "cache_status", "tls_protocol")
    @classmethod
    def _normalize_enrichment(cls, value: str | None) -> str | None:
        """Normalize enrichment matchers to their stored canonical form."""
        if value is None:
            return None
        return value.strip()

    @field_validator("country")
    @classmethod
    def _normalize_country(cls, value: str | None) -> str | None:
        """Country through the shared selector allowlist (PAR-09).

        ``UNKNOWN`` selects rows with no known country; ISO codes
        match exactly (case-insensitive input, uppercase storage).
        Anything else — including a blank that reaches the contract
        directly — raises instead of silently widening.
        """
        if value is None:
            return None
        return normalize_country_selector(value)

    @model_validator(mode="after")
    def _enrichment_consistent(self) -> "AnalyticsFilter":
        import math as _math
        import re as _re

        if self.server_host is not None:
            host = self.server_host.strip().lower()
            if not host or len(host) > 253 or "\x00" in host:
                raise ValueError("server_host must be a hostname of 1..253 characters")
            object.__setattr__(self, "server_host", host)
        if self.http_version is not None:
            version = self.http_version.strip()
            if not _re.match(r"^HTTP/\d+(\.\d+)?$", version):
                raise ValueError("http_version must look like HTTP/1.1 or HTTP/2")
            object.__setattr__(self, "http_version", version)
        if self.mime_type is not None:
            media = self.mime_type.split(";", 1)[0].strip().lower()
            if not _re.match(r"^[^/\s;]{1,64}/[^;\s]{1,64}$", media):
                raise ValueError("mime_type must be a type/subtype media range")
            object.__setattr__(self, "mime_type", media)
        if self.cache_status is not None:
            cache = self.cache_status.strip().upper()
            if not _re.match(r"^[A-Z_]{1,32}$", cache):
                raise ValueError("cache_status must be an uppercase cache token")
            object.__setattr__(self, "cache_status", cache)
        if self.tls_protocol is not None:
            tls = self.tls_protocol.strip()
            if not _re.match(r"^[A-Za-z0-9._-]{1,32}$", tls):
                raise ValueError("tls_protocol must be a 1..32 character token")
            object.__setattr__(self, "tls_protocol", tls)
        for name in ("timing_min_ms", "timing_max_ms"):
            bound = getattr(self, name)
            if bound is not None and not _math.isfinite(bound):
                raise ValueError(f"{name} must be finite")
        if (
            self.timing_min_ms is not None
            and self.timing_max_ms is not None
            and self.timing_min_ms > self.timing_max_ms
        ):
            raise ValueError("timing_min_ms must not exceed timing_max_ms")
        return self

    @model_validator(mode="after")
    def _status_consistent(self) -> "AnalyticsFilter":
        if (
            self.status is not None
            and self.status_class is not None
            and f"{self.status // 100}xx" != self.status_class
        ):
            raise ValueError("status and status_class contradict each other")
        if self.path_exact is not None:
            if "\x00" in self.path_exact or not self.path_exact.strip():
                raise ValueError("path_exact must be a non-blank path")
            if self.path_prefix is not None and not self.path_exact.startswith(self.path_prefix):
                raise ValueError("path_exact contradicts path_prefix")
        return self


class TopPathsQuery(BaseModel):
    filt: AnalyticsFilter
    sort: TopPathSort = "requests_desc"


class TopReferrersQuery(BaseModel):
    filt: AnalyticsFilter
    sort: TopReferrerSort = "requests_desc"


SlowEndpointSort = Literal["avg_desc", "p95_desc", "requests_desc", "max_desc"]


class SlowEndpointsQuery(BaseModel):
    """Slow measured endpoints: one allowlisted server sort, stable paging."""

    filt: AnalyticsFilter
    sort: SlowEndpointSort = "avg_desc"


class BotTableQuery(BaseModel):
    filt: AnalyticsFilter
    sort: BotTableSort = "requests_desc"


class ExplorerQuery(BaseModel):
    filt: AnalyticsFilter
    sort: ExplorerSort = "newest"


#: Request-journey list sorts. Every option maps to ONE fixed ORDER BY
#: fragment in ``queries.journey_list``; ties break by stable journey
#: ID so paging is deterministic. ``requests_desc`` ranks by the
#: filtered (shown) request count, never the unfiltered total.
JourneySort = Literal[
    "requests_desc",
    "start_asc",
    "start_desc",
    "duration_desc",
]


class JourneyQuery(BaseModel):
    """Paginated request-journey list over one shared filter.

    ``min_requests`` keeps only journeys with at least that many
    filtered (shown) requests; the unfiltered per-journey total is
    always reported alongside so filters never silently narrow a
    journey.
    """

    filt: AnalyticsFilter
    sort: JourneySort = "requests_desc"
    min_requests: int = Field(default=1, ge=1, le=MAX_LIMIT)


class JourneyTimelineQuery(BaseModel):
    """Bounded chronological timeline for one journey key.

    The journey is re-derived from the authorized site/source event
    stream (same gap rule as the list), so the timeline agrees with
    the list even when filters hide the journey's first request.
    """

    filt: AnalyticsFilter
    client_pseudonym: str = Field(min_length=1, max_length=128)
    user_agent: str | None = Field(default=None, max_length=4096)
    journey_start: datetime

    @field_validator("journey_start")
    @classmethod
    def _require_tz_start(cls, value: datetime) -> datetime:
        return _as_utc(value)


class JourneyIdQuery(BaseModel):
    """Opaque journey lookup: resolve a listed ``journey_id`` to its timeline.

    The list response carries ``journey_id``/``client_pseudonym``/
    ``started_at`` but never the full stored User-Agent (agents
    render truncated), so callers must not guess the agent text.
    The server re-derives the journeys in the validated
    site/source/window scope, matches the opaque ID exactly, and
    then serves the same bounded timeline. ``None`` and empty-string
    agents stay distinct keys; no history outside the validated
    window is ever read and no original address is exposed.
    """

    filt: AnalyticsFilter
    client_pseudonym: str = Field(min_length=1, max_length=128)
    journey_start: datetime
    journey_id: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")

    @field_validator("journey_start")
    @classmethod
    def _require_tz_start(cls, value: datetime) -> datetime:
        return _as_utc(value)

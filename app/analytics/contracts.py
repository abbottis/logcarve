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

MAX_LIMIT = 1000
MAX_WINDOW_DAYS = 366
MAX_SEARCH_LEN = 128
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
    referer_host: str | None = Field(default=None, min_length=1, max_length=253)
    search: str | None = Field(default=None, min_length=1, max_length=MAX_SEARCH_LEN)
    traffic: TrafficFilter = "all"
    bot: str | None = Field(default=None, min_length=1, max_length=64)
    category: str | None = Field(default=None, min_length=1, max_length=64)
    provider: str | None = Field(default=None, min_length=1, max_length=120)
    purpose: str | None = Field(default=None, min_length=1, max_length=120)
    limit: int = Field(default=100, ge=1, le=MAX_LIMIT)
    offset: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _status_consistent(self) -> "AnalyticsFilter":
        if (
            self.status is not None
            and self.status_class is not None
            and f"{self.status // 100}xx" != self.status_class
        ):
            raise ValueError("status and status_class contradict each other")
        return self


class TopPathsQuery(BaseModel):
    filt: AnalyticsFilter
    sort: TopPathSort = "requests_desc"


class TopReferrersQuery(BaseModel):
    filt: AnalyticsFilter
    sort: TopReferrerSort = "requests_desc"


class BotTableQuery(BaseModel):
    filt: AnalyticsFilter
    sort: BotTableSort = "requests_desc"


class ExplorerQuery(BaseModel):
    filt: AnalyticsFilter
    sort: ExplorerSort = "newest"

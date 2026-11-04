"""T4 contract tests: validated, bounded analytics filters and windows."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.analytics.contracts import MAX_WINDOW_DAYS, AnalyticsFilter, TimeWindow

FROM = datetime(2026, 10, 27, tzinfo=UTC)
TO = datetime(2026, 10, 28, tzinfo=UTC)


def _window(time_from=FROM, time_to=TO) -> TimeWindow:
    return TimeWindow(time_from=time_from, time_to=time_to)


def _filt(**overrides) -> AnalyticsFilter:
    base = {"site_id": "default", "window": _window()}
    base.update(overrides)
    return AnalyticsFilter(**base)


def test_window_normalizes_offsets_to_utc():
    window = TimeWindow(
        time_from=datetime(2026, 10, 27, 10, 0, tzinfo=UTC),
        time_to=datetime(2026, 10, 27, 12, 0, tzinfo=UTC),
    )
    assert window.time_from == datetime(2026, 10, 27, 10, 0, tzinfo=UTC)


def test_naive_datetimes_rejected():
    with pytest.raises(ValidationError):
        _window(time_from=datetime(2026, 10, 27), time_to=TO)


def test_inverted_and_oversized_windows_rejected():
    with pytest.raises(ValidationError):
        _window(time_from=TO, time_to=FROM)
    with pytest.raises(ValidationError):
        _window(time_from=FROM, time_to=datetime(2028, 10, 27, tzinfo=UTC))


def test_filter_bounds_and_defaults():
    filt = _filt()
    assert (filt.limit, filt.offset) == (100, 0)
    with pytest.raises(ValidationError):
        _filt(limit=0)
    with pytest.raises(ValidationError):
        _filt(limit=1001)
    with pytest.raises(ValidationError):
        _filt(offset=-1)
    with pytest.raises(ValidationError):
        _filt(status=99)
    with pytest.raises(ValidationError):
        _filt(status=600)


def test_unknown_sort_literal_rejected():
    from app.analytics.contracts import TopPathsQuery

    with pytest.raises(ValidationError):
        TopPathsQuery(filt=_filt(), sort="requests_asc")


def test_window_exact_boundary_and_one_microsecond_over():
    exact = TimeWindow(time_from=FROM, time_to=FROM + timedelta(days=MAX_WINDOW_DAYS))
    assert (exact.time_to - exact.time_from) == timedelta(days=MAX_WINDOW_DAYS)
    with pytest.raises(ValidationError):
        TimeWindow(
            time_from=FROM,
            time_to=FROM + timedelta(days=MAX_WINDOW_DAYS, microseconds=1),
        )


def test_window_bound_uses_duration_not_floored_days():
    # A 366-day-plus-12h window has .days == 366 but exceeds the bound.
    with pytest.raises(ValidationError):
        TimeWindow(time_from=FROM, time_to=FROM + timedelta(days=MAX_WINDOW_DAYS, hours=12))

"""Stage A owner-review unit checks: labels stay presentation-only and
offsets are truthful at controlled dates.

Data contracts (rule IDs, API fields, stored values, canonical timezone
keys) are asserted unchanged while display helpers strip prefixes,
map categories and format signed offsets including DST, fractions,
Etc/GMT reversal and historical sub-minute values. Synthetic only.
"""

from datetime import datetime

import pytest

from app.web import routes as routes_mod
from app.web import timezones as tzmod


def _instant(text):
    return datetime.fromisoformat(text)


def test_display_bot_title_strips_single_leading_claim():
    assert routes_mod.display_bot_title("Claimed Googlebot") == "Googlebot"
    assert routes_mod.display_bot_title("Googlebot") == "Googlebot"
    assert routes_mod.display_bot_title("Claimed") == "Claimed"
    # Only a leading prefix is stripped; inner text is never rewritten.
    assert routes_mod.display_bot_title("Proclaimed Bots") == "Proclaimed Bots"
    assert routes_mod.display_bot_title("Claimed Claimed X") == "Claimed X"


def test_category_labels_have_no_underscores_and_map():
    assert routes_mod.category_label("ai_crawler") == "AI crawlers"
    assert routes_mod.category_label("search_crawler") == "Search crawlers"
    assert routes_mod.category_label("seo_tool") == "SEO tools"
    assert routes_mod.category_label("automation_tool") == "Automation tools"
    for value in (
        "search_crawler",
        "ai_crawler",
        "seo_tool",
        "monitoring",
        "generic_bot",
        "social_bot",
        "federation_crawler",
        "feed_fetcher",
        "automation_tool",
        "suspected_automation",
        "unknown",
    ):
        assert "_" not in routes_mod.category_label(value), value


def test_provider_purpose_passthrough_and_unclaimed():
    assert routes_mod.provider_label("OpenAI") == "OpenAI"
    assert routes_mod.provider_label(None) == "Unspecified"
    assert routes_mod.purpose_label("AI Crawler") == "AI Crawler"
    assert routes_mod.purpose_label(None) == "Unspecified"


def test_status_label_known_and_unregistered():
    assert routes_mod.status_label(404) == "404 · Not Found"
    assert routes_mod.status_label(200) == "200 · OK"
    assert routes_mod.status_label(599) == "Status 599 (unregistered)"
    assert routes_mod.status_label(150) == "Status 150 (unregistered)"


def test_human_bytes_readable():
    assert routes_mod.human_bytes(None) == "—"
    assert routes_mod.human_bytes(0) == "0 B"
    assert routes_mod.human_bytes(3334) == "3.3 KiB"
    assert routes_mod.human_bytes(1024) == "1.0 KiB"
    assert routes_mod.human_bytes(5 * 1024 * 1024) == "5.0 MiB"


def test_offset_winter_summer_dst():
    winter = _instant("2026-01-27T00:00:00+00:00")
    summer = _instant("2026-07-27T00:00:00+00:00")
    assert tzmod.format_offset_suffix("Europe/Berlin", winter) == "UTC+01:00"
    assert tzmod.format_offset_suffix("Europe/Berlin", summer) == "UTC+02:00"
    # The reference is the window start, not the review date.
    assert tzmod.format_offset_suffix("Europe/Berlin", winter) != tzmod.format_offset_suffix(
        "Europe/Berlin", summer
    )


def test_offset_sign_fractional_and_etc_reverse():
    ref = _instant("2026-10-27T00:00:00+00:00")
    assert tzmod.format_offset_suffix("Asia/Kathmandu", ref) == "UTC+05:45"
    # St. John's is on daylight time (-02:30) in late October.
    assert tzmod.format_offset_suffix("America/St_Johns", ref) == "UTC-02:30"
    assert (
        tzmod.format_offset_suffix("America/St_Johns", _instant("2026-01-27T00:00:00+00:00"))
        == "UTC-03:30"
    )
    assert tzmod.format_offset_suffix("UTC", ref) == "UTC+00:00"
    # Etc/GMT signs are reversed by POSIX convention: Etc/GMT+2 is -02:00.
    assert tzmod.format_offset_suffix("Etc/GMT+2", ref) == "UTC-02:00"


def test_offset_historical_subminute_seconds():
    # New York mean time before standard zones: UTC-04:56:02.
    ref = _instant("1880-01-01T00:00:00+00:00")
    assert tzmod.format_offset_suffix("America/New_York", ref) == "UTC-04:56:02"


def test_offset_malformed_never_guesses():
    assert tzmod.offset_at("Nope/Zone", _instant("2026-10-27T00:00:00+00:00")) is None
    assert (
        tzmod.format_offset_suffix("Nope/Zone", _instant("2026-10-27T00:00:00+00:00"))
        == "UTC offset unavailable"
    )


def test_display_options_carry_offset_but_exact_values():
    ref = _instant("2026-01-27T00:00:00+00:00")
    options = tzmod.display_options(None, ref)
    assert len(options) == len(tzmod.catalog_keys()) > 100, "every supported key offered once"
    values = [entry["value"] for entry in options]
    assert len(set(values)) == len(values), "no duplicate option values"
    labels = {entry["value"]: entry["label"] for entry in options}
    assert labels["Europe/Berlin"] == "Europe/Berlin — UTC+01:00"
    assert labels["Asia/Kathmandu"] == "Asia/Kathmandu — UTC+05:45"
    assert labels["UTC"] == "UTC — UTC+00:00"


def test_zone_objects_cached_bounded():
    from zoneinfo import ZoneInfoNotFoundError

    assert tzmod._zone("Europe/Berlin") is tzmod._zone("Europe/Berlin")
    assert tzmod._zone.cache_info().maxsize == 128
    with pytest.raises(ZoneInfoNotFoundError):
        tzmod._zone("Nope/Zone")

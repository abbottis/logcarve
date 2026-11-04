"""T7 egress tests: forbidden shapes fail closed, timestamps survive."""

import pytest

from app.ai import egress


def test_clean_aggregates_pass():
    text = "summary site default: requests 10, errors_4xx 2, window 2026-10-27/28"
    assert egress.check_outgoing(text, context="test") == text


def test_iso_timestamps_and_bare_times_pass():
    stamps = [
        "window 2026-10-27T00:00:00+00:00 to 2026-10-28T00:00:00+00:00",
        "observed 2026-10-31T12:30:00+00:00 with time 12:30:00 and 00:00:00",
        "2026-10-31T12:30:00.123456+00:00",
    ]
    for stamp in stamps:
        assert egress.check_outgoing(stamp, context="test") == stamp


@pytest.mark.parametrize(
    "payload,code",
    [
        ("client 203.0.113.7 made 5 requests", "raw_network_address"),
        ("agent 2001:db8::1 claimed crawl", "raw_network_address"),
        ("agent fe80::1 repeated errors", "raw_network_address"),
        (
            '203.0.113.7 - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
            "raw_network_address",
        ),
        (
            'host-01 - - [27/Oct/2026:10:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"',
            "raw_log_line",
        ),
        ("see ?api_key=ABCDEF1234 for details", "query_secret"),
        ("Password: hunter2 in the header", "credential_material"),
        ("use lc_abcdefghijklmnop as token", "credential_material"),
        ("-----BEGIN RSA PRIVATE KEY-----", "credential_material"),
        ("visit https://user:pass@example.org/x", "credential_material"),
        ("x" * (egress.MAX_OUTGOING_CHARS + 1), "payload_too_large"),
    ],
)
def test_forbidden_shapes_fail_closed(payload, code):
    with pytest.raises(egress.EgressViolation) as excinfo:
        egress.check_outgoing(payload, context="test")
    assert excinfo.value.code == code


def test_evidence_serializer_allowlists_fields_and_masks_addresses():
    result = {
        "site_id": "default",
        "totals": {"requests": 3},
        "status_distribution": [{"status": 200, "requests": 3}],
        "duration": {"available": False},
        "warnings": [],
        "extra_new_field": "must not cross",
        "time_range": {"time_from": "2026-10-27T00:00:00+00:00"},
    }
    payload = egress.serialize_evidence("get_summary", result)
    assert "extra_new_field" not in payload
    # Time windows are explicitly allowed across the boundary.
    assert payload["time_range"] == {"time_from": "2026-10-27T00:00:00+00:00"}
    assert payload["totals"] == {"requests": 3}


def test_evidence_masks_ip_shapes_but_blocks_smuggled_secrets():
    result = {
        "items": [{"user_agent": "bot from 203.0.113.7 at 12:30:00", "requests": 2}],
        "total": 1,
    }
    payload = egress.serialize_evidence("get_crawler_claims", result)
    agent = payload["items"][0]["user_agent"]
    assert "203.0.113.7" not in agent
    assert "[redacted-address]" in agent
    assert "12:30:00" in agent
    hostile = {"items": [{"user_agent": "x lc_smuggledtokenvalue", "requests": 1}], "total": 1}
    with pytest.raises(egress.EgressViolation):
        egress.serialize_evidence("get_crawler_claims", hostile)


def test_unknown_tool_has_no_evidence_contract():
    with pytest.raises(egress.EgressViolation) as excinfo:
        egress.serialize_evidence("run_sql", {"rows": []})
    assert excinfo.value.code == "unknown_tool"


@pytest.mark.parametrize(
    "payload",
    [
        "::1",
        "::",
        "from ::1 with 3 hits",
        "[::1]",
        "fe80::1",
        "2001:db8::1",
        "fe80::1%eth0",
        "::ffff:203.0.113.7",
        "2001:db8:0:0:0:0:0:1",
    ],
)
def test_compressed_and_bracketed_ipv6_forms_blocked(payload):
    with pytest.raises(egress.EgressViolation) as excinfo:
        egress.check_outgoing(payload, context="test")
    assert excinfo.value.code == "raw_network_address"


@pytest.mark.parametrize(
    "payload",
    [
        "at 2026-10-31T12:30:00+00:00 sharp",
        "window 2026-10-27T00:00:00+00:00 to 2026-10-28T00:00:00+00:00",
        "logged at 12:30:00 and again 00:00:00",
        "date 2026-10-31 with count 7",
    ],
)
def test_timestamps_and_bare_times_pass(payload):
    assert egress.check_outgoing(payload, context="test") == payload


def test_evidence_masks_compressed_ipv6_without_harming_timestamps():
    result = {
        "items": [{"user_agent": "probe ::1 at 2026-10-31T12:30:00+00:00", "requests": 1}],
        "total": 1,
    }
    payload = egress.serialize_evidence("get_crawler_claims", result)
    agent = payload["items"][0]["user_agent"]
    assert "::1" not in agent
    assert "2026-10-31T12:30:00+00:00" in agent

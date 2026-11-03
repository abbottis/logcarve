"""Fail-closed adjudication of the redacted Gitleaks report (CI secret policy).

Covers the exact reviewed metadata, unknown findings, forged
fingerprints, metadata mismatches, malformed/missing reports and
scanner execution-error/exit-status mismatches. Failure diagnostics
must never carry scanner Secret/Match payloads.
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
HELPER = ROOT / "scripts" / "ci" / "check_gitleaks_report.py"
EXPECTED = ROOT / "scripts" / "ci" / "reviewed_gitleaks_findings.json"

_spec = importlib.util.spec_from_file_location("check_gitleaks_report", HELPER)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ReportError = _mod.ReportError
adjudicate = _mod.adjudicate
load_expected = _mod.load_expected
load_findings = _mod.load_findings
main = _mod.main

FORBIDDEN = "SHOULD-NEVER-APPEAR-SECRET-aa11"


def _finding(fingerprint, file, rule, line, commit):
    return {
        "Fingerprint": fingerprint,
        "File": file,
        "RuleID": rule,
        "StartLine": line,
        "Commit": commit,
        "Secret": FORBIDDEN,
        "Match": FORBIDDEN,
    }


def _expected():
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def _report_findings():
    return [
        _finding(
            "986f46e8a8daea2aee86e9484224be47e3fdb022"
            ":tests/unit/test_native_http_boundary.py:generic-api-key:32",
            "tests/unit/test_native_http_boundary.py",
            "generic-api-key",
            32,
            "986f46e8a8daea2aee86e9484224be47e3fdb022",
        ),
        _finding(
            "016b458744e33713980b081e7c31c6c56bbe5a58"
            ":tests/integration/test_parity_t5a.py:generic-api-key:574",
            "tests/integration/test_parity_t5a.py",
            "generic-api-key",
            574,
            "016b458744e33713980b081e7c31c6c56bbe5a58",
        ),
        _finding(
            "b52a9fb77db80a793d774f895cefc2b9e585341a:docs/technical-spec.md:generic-api-key:787",
            "docs/technical-spec.md",
            "generic-api-key",
            787,
            "b52a9fb77db80a793d774f895cefc2b9e585341a",
        ),
    ]


def test_accepted_exact_known_metadata():
    matched = adjudicate(_report_findings(), _expected(), 1)
    assert len(matched) == 3


def test_rejects_unknown_fourth_finding():
    findings = _report_findings() + [
        _finding("x:app/x.py:generic-api-key:1", "app/x.py", "generic-api-key", 1, "x" * 40)
    ]
    with pytest.raises(ReportError) as excinfo:
        adjudicate(findings, _expected(), 1)
    assert FORBIDDEN not in str(excinfo.value)


def test_rejects_forged_fingerprint_metadata_mismatch():
    forged = _report_findings()
    forged[0] = dict(
        forged[0],
        Commit="0" * 40,
        Fingerprint="0" * 40 + ":tests/unit/test_native_http_boundary.py:generic-api-key:32",
    )
    with pytest.raises(ReportError) as excinfo:
        adjudicate(forged, _expected(), 1)
    assert FORBIDDEN not in str(excinfo.value)


def test_rejects_line_mismatch():
    wrong = _report_findings()
    wrong[1] = dict(wrong[1], StartLine=575)
    with pytest.raises(ReportError):
        adjudicate(wrong, _expected(), 1)


def test_rejects_missing_reviewed_finding():
    with pytest.raises(ReportError):
        adjudicate(_report_findings()[:2], _expected(), 1)


def test_rejects_malformed_report(tmp_path):
    bad = tmp_path / "report.json"
    bad.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(ReportError):
        load_findings(bad, 1)
    broken = tmp_path / "broken.json"
    broken.write_text("[1, 2", encoding="utf-8")
    with pytest.raises(ReportError):
        load_findings(broken, 1)


def test_rejects_missing_report(tmp_path):
    with pytest.raises(ReportError):
        load_findings(tmp_path / "absent.json", 1)


def test_rejects_scanner_execution_error(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    with pytest.raises(ReportError):
        load_findings(report, 2)


def test_rejects_exit_status_mismatch(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    with pytest.raises(ReportError):
        adjudicate([], _expected(), 0)
    full = tmp_path / "full.json"
    full.write_text(json.dumps(_report_findings()), encoding="utf-8")
    with pytest.raises(ReportError):
        load_findings(full, 0)


def test_rejects_malformed_expected(tmp_path):
    bad = tmp_path / "expected.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ReportError):
        load_expected(bad)


def test_rejects_fingerprint_only_forgery():
    """Changing ONLY Fingerprint (metadata intact) must reject, not exit 0."""
    forged = _report_findings()
    forged[0] = dict(forged[0], Fingerprint="forged-fingerprint")
    with pytest.raises(ReportError):
        adjudicate(forged, _expected(), 1)


def test_rejects_missing_fingerprint():
    missing = _report_findings()
    entry = dict(missing[0])
    del entry["Fingerprint"]
    missing[0] = entry
    with pytest.raises(ReportError):
        adjudicate(missing, _expected(), 1)


def test_rejects_self_inconsistent_expected(tmp_path):
    bad = tmp_path / "expected.json"
    entries = _expected()
    entries[0] = dict(entries[0], fingerprint="forged-fingerprint")
    bad.write_text(json.dumps(entries), encoding="utf-8")
    with pytest.raises(ReportError):
        load_expected(bad)


def test_diagnostics_never_echo_untrusted_keys(tmp_path, capsys):
    sentinel = "synthetic-private-sentinel-key"
    report = tmp_path / "report.json"
    report.write_text(json.dumps([{sentinel: "x"}]), encoding="utf-8")
    assert main(["--report", str(report), "--expected", str(EXPECTED), "--gitleaks-exit", "1"]) == 1
    assert sentinel not in capsys.readouterr().out
    described = _mod._safe_describe({sentinel: "x"})
    assert sentinel not in described


def test_rejects_invalid_utf8_without_traceback(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_bytes(b'[{"Commit": "\xff\xfe invalid"}]')
    with pytest.raises(ReportError):
        load_findings(report, 1)
    assert main(["--report", str(report), "--expected", str(EXPECTED), "--gitleaks-exit", "1"]) == 1
    out = capsys.readouterr().out
    assert "Traceback" not in out
    assert "GITLEAKS_REJECTED" in out


def test_main_never_prints_secret_payloads(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            _report_findings()
            + [_finding("y:app/y.py:generic-api-key:2", "app/y.py", "generic-api-key", 2, "y" * 40)]
        ),
        encoding="utf-8",
    )
    assert main(["--report", str(report), "--expected", str(EXPECTED), "--gitleaks-exit", "1"]) == 1
    assert FORBIDDEN not in capsys.readouterr().out

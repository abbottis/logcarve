"""Fail-closed adjudication of a redacted Gitleaks JSON report.

Every reported finding must match one entry of the exact reviewed
metadata record (historical fingerprint plus file/rule/line/commit);
any unknown finding, missing/forged scanner Fingerprint, metadata
mismatch, malformed or missing report, or scanner execution failure
rejects the run.

The scanner-provided ``Fingerprint`` field is untrusted input: it must
be a non-empty string exactly equal to the recomputed metadata
composite (``Commit:File:RuleID:StartLine``) AND to the matched
reviewed entry's fingerprint. Reviewed entries must themselves be
self-consistent (their recorded fingerprint equals their own
commit/file/rule/line composite).

Scanner ``Secret``/``Match`` values are never printed, even on
rejection: diagnostics carry only fixed shape words, report indexes,
counts and trusted reviewed metadata — never untrusted report keys,
fields or arbitrary values. Undecodable bytes and malformed JSON fail
closed without tracebacks.
"""

import argparse
import json
from pathlib import Path

REQUIRED_ENTRY_KEYS = ("fingerprint", "file", "rule", "line", "commit")


class ReportError(Exception):
    """Adjudication rejection; message carries safe metadata only."""


def _safe_describe(value: object) -> str:
    """Fixed type/shape/count words; never untrusted keys or values."""
    if isinstance(value, dict):
        return f"object with {len(value)} entries"
    if isinstance(value, list):
        return f"list of length {len(value)}"
    return type(value).__name__


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"{label} unreadable: {path}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReportError(f"{label} must be valid UTF-8") from exc


def _parse_json(raw: str, label: str) -> object:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{label} malformed: {exc.msg}") from exc
    except ValueError as exc:
        raise ReportError(f"{label} malformed") from exc


def _entry_composite(entry: dict) -> str:
    return f"{entry['commit']}:{entry['file']}:{entry['rule']}:{entry['line']}"


def load_expected(path: Path) -> list[dict]:
    raw = _read_text(path, "expected metadata")
    data = _parse_json(raw, "expected metadata")
    if not isinstance(data, list) or not data:
        raise ReportError(f"expected metadata must be a non-empty list, got {_safe_describe(data)}")
    seen: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            raise ReportError(f"expected entry must be an object, got {_safe_describe(entry)}")
        for key in REQUIRED_ENTRY_KEYS:
            if key not in entry:
                raise ReportError(f"expected entry missing key: {key}")
        fingerprint = entry["fingerprint"]
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ReportError("expected entry fingerprint must be a non-empty string")
        if fingerprint in seen:
            raise ReportError("expected metadata holds a duplicate fingerprint")
        seen.add(fingerprint)
        for key in ("file", "rule", "commit"):
            if not isinstance(entry[key], str) or not entry[key]:
                raise ReportError(f"expected entry {key} must be a non-empty string")
        if not isinstance(entry["line"], int) or isinstance(entry["line"], bool):
            raise ReportError("expected entry line must be an integer")
        if fingerprint != _entry_composite(entry):
            raise ReportError("expected entry fingerprint is not self-consistent")
    return data


def load_findings(path: Path, gitleaks_exit: int) -> list[dict]:
    if gitleaks_exit not in (0, 1):
        raise ReportError(f"scanner execution failed with exit code {gitleaks_exit}")
    raw = _read_text(path, "scanner report")
    data = _parse_json(raw, "scanner report")
    if not isinstance(data, list):
        raise ReportError(f"scanner report must be a JSON list, got {_safe_describe(data)}")
    if gitleaks_exit == 0 and data:
        raise ReportError(
            f"scanner exit 0 (clean) contradicts a non-empty report of {len(data)} findings"
        )
    return data


def composite_fingerprint(finding: dict) -> str:
    try:
        commit = finding["Commit"]
        file = finding["File"]
        rule = finding["RuleID"]
        line = finding["StartLine"]
    except KeyError as exc:
        raise ReportError(f"finding missing scanner field: {exc}") from exc
    if not all(isinstance(v, str) and v for v in (commit, file, rule)):
        raise ReportError("finding Commit/File/RuleID must be non-empty strings")
    if not isinstance(line, int) or isinstance(line, bool):
        raise ReportError("finding StartLine must be an integer")
    return f"{commit}:{file}:{rule}:{line}"


def provided_fingerprint(finding: dict, index: int) -> str:
    try:
        fingerprint = finding["Fingerprint"]
    except KeyError as exc:
        raise ReportError(f"finding at report index {index} omits Fingerprint") from exc
    if not isinstance(fingerprint, str) or not fingerprint:
        raise ReportError(f"finding at report index {index} has no usable Fingerprint")
    return fingerprint


def adjudicate(findings: list[dict], expected: list[dict], gitleaks_exit: int) -> list[str]:
    if gitleaks_exit == 0:
        if expected:
            raise ReportError(
                "scanner reported clean but "
                f"{len(expected)} reviewed findings are recorded: re-review required"
            )
        return []
    matched: list[str] = []
    remaining = {entry["fingerprint"]: entry for entry in expected}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ReportError(
                f"finding at report index {index} must be an object, got {_safe_describe(finding)}"
            )
        recomputed = composite_fingerprint(finding)
        provided = provided_fingerprint(finding, index)
        if provided != recomputed:
            raise ReportError(f"finding at report index {index} carries a forged Fingerprint")
        entry = remaining.pop(recomputed, None)
        if entry is None:
            raise ReportError(
                f"unknown or forged finding at report index {index}: "
                f"no reviewed-metadata match ({len(remaining)} reviewed unmatched)"
            )
        if provided != entry["fingerprint"]:
            raise ReportError(f"finding at report index {index} mismatches reviewed metadata")
        for scanner_key, entry_key in (
            ("File", "file"),
            ("RuleID", "rule"),
            ("StartLine", "line"),
            ("Commit", "commit"),
        ):
            if finding[scanner_key] != entry[entry_key]:
                raise ReportError(
                    f"metadata mismatch for reviewed entry {entry['fingerprint']}: "
                    f"{entry_key} differs"
                )
        matched.append(entry["fingerprint"])
    if remaining:
        raise ReportError(f"scanner missed {len(remaining)} reviewed findings: {sorted(remaining)}")
    return matched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Adjudicate a redacted Gitleaks report.")
    parser.add_argument("--report", required=True, help="Path to the Gitleaks JSON report.")
    parser.add_argument("--expected", required=True, help="Path to reviewed findings metadata.")
    parser.add_argument("--gitleaks-exit", required=True, type=int, help="Scanner exit code.")
    args = parser.parse_args(argv)
    try:
        expected = load_expected(Path(args.expected))
        findings = load_findings(Path(args.report), args.gitleaks_exit)
        matched = adjudicate(findings, expected, args.gitleaks_exit)
    except ReportError as exc:
        print(f"GITLEAKS_REJECTED {exc}")
        return 1
    except Exception:  # noqa: BLE001 — fail closed without traceback payloads
        print("GITLEAKS_REJECTED unexpected adjudication failure")
        return 1
    print(f"GITLEAKS_ADJUDICATED findings={len(matched)} reviewed={len(expected)}")
    for fingerprint in matched:
        print(f"reviewed: {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

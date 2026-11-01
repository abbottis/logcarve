"""Bounded administrator custom log-format mappings (T1a).

A custom format is a JSON document validated before use::

    {"format_id": "custom-acme",
     "pattern": "^(?P<host>\\\\S+) ... \"(?P<request>[^\"]*)\" ...",
     "time_format": "combined",
     "timing": {"request_time": {"unit": "s"}, "upstream_time": {"unit": "ms", "multi": true}},
     "max_pattern_len": 2048}

Only allowlisted named groups may appear, at least the required set must
appear, and named-group bodies are restricted to nesting-free constructs
with no backreferences and no stacked or overlapping open quantifiers.
Those allowlists shrink the hazard surface but cannot enumerate every
ambiguous construct (notably ambiguity *outside* named groups, such as a
trailing ``(?:a|aa)+$``) — so the real guarantee is a proven
per-operation match timeout from the ``regex`` package
(``Pattern.match(..., timeout=...)`` raising built-in ``TimeoutError``),
mapped to the fixed ``custom_timeout`` rejection code. No ``eval``, no
code, no shell, no thread timers.

At parse time the same line/field bounds as the presets apply, plus the
hard match timeout: matching runs against lines already capped at
``max_line_bytes`` and every captured field is length-checked before use.
"""

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

import regex as _rx

REQUIRED_GROUPS = frozenset({"host", "time", "request", "status"})
OPTIONAL_GROUPS = frozenset(
    {
        "ident",
        "user",
        "size",
        "bytes",
        "referer",
        "user_agent",
        "vhost",
        "cache",
        "request_time",
        "mime",
        "tls",
        "upstream_time",
    }
)
ALLOWED_GROUPS = REQUIRED_GROUPS | OPTIONAL_GROUPS
TIMING_GROUPS = frozenset({"request_time", "upstream_time"})
ALLOWED_UNITS = frozenset({"s", "ms", "us"})

MAX_PATTERN_LEN = 2048
MAX_FORMAT_ID_LEN = 64
# Hard per-operation match budget in seconds. Ambiguous constructs that
# survive the static allowlists (notably outside named groups) abort via
# the regex engine's own timeout instead of burning unbounded CPU; no
# thread timer is used, so nothing keeps running after the abort.
CUSTOM_MATCH_TIMEOUT_S = 0.5
# Upper bound on a custom-format JSON file: one byte more is read so an
# oversize file is rejected without ever buffering the whole file.
MAX_SPEC_BYTES = 65536
_FORMAT_ID_RE = re.compile(r"^custom-[a-z0-9][a-z0-9_-]{0,63}$")
_GROUP_RE = re.compile(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>")
_BACKREF_RE = re.compile(r"\\[1-9]|\(\?P=")
# Stripped bodies (escapes/classes folded to e/C) may use word chars,
# safe literals, single quantifiers and bounded {m,n} repetition only.
_SAFE_STRIPPED_RE = re.compile(r"^(?:[\w:;/., _+@%#~|'=$-]|e|C|[+*?{}])+$")


def _skip_class(body: str, start: int) -> int | None:
    """End index (exclusive) of the class opening at ``start``, or None.

    Escape-aware: ``\\]`` never closes the class. A ``]`` immediately
    after ``[``/``[^`` is a literal (so ``[^]]`` works).
    """
    n = len(body)
    j = start + 1
    if j < n and body[j] == "^":
        j += 1
    if j < n and body[j] == "]":
        j += 1
    while j < n:
        if body[j] == "\\":
            j += 2
            continue
        if body[j] == "]":
            return j + 1
        j += 1
    return None


def _strip_classes(body: str) -> str | None:
    """Replace escapes with ``e`` and character classes with ``C``.

    Returns ``None`` when escapes or classes are unterminated.
    """
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        char = body[i]
        if char == "\\":
            if i + 1 >= n:
                return None
            out.append("e")
            i += 2
            continue
        if char == "[":
            end = _skip_class(body, i)
            if end is None:
                return None
            out.append("C")
            i = end
            continue
        out.append(char)
        i += 1
    return "".join(out)


class CustomFormatError(ValueError):
    """A custom mapping or its use failed validation. Fixed codes only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def is_custom_format_id(value: object) -> bool:
    """Whether ``value`` names the administrator ``custom-`` namespace."""
    return isinstance(value, str) and bool(_FORMAT_ID_RE.match(value))


def _check_body_safe(body: str) -> bool:
    """Accept only nesting-free bodies built from safe atoms."""
    if _BACKREF_RE.search(body):
        return False
    stripped = _strip_classes(body)
    if stripped is None or not stripped:
        return False
    # No grouping of any kind inside a named-group body: with parens gone,
    # ambiguous nested quantification such as ``(a+)+`` cannot be written.
    if "(" in stripped or ")" in stripped:
        return False
    # No stacked quantifiers (``a++``/``a+*``); Python ``re`` rejects most
    # of these already, this fails closed on the rest.
    if re.search(r"[+*?][+*?]", stripped):
        return False
    # At most one unbounded quantifier per body: overlapping open runs
    # such as ``.*.*`` are the classic backtracking hazard. Bounded
    # ``{m,n}`` repetition and single ``?`` optionals stay allowed.
    if len(re.findall(r"[*+]", stripped)) > 1:
        return False
    if not _SAFE_STRIPPED_RE.match(stripped):
        return False
    # Bounded repetition only, with small explicit bounds.
    for repeat in re.findall(r"\{([^}]*)\}", stripped):
        bounds = [item for item in repeat.split(",") if item]
        if not bounds or any(not item.isdigit() or int(item) > 9999 for item in bounds):
            return False
    return True


@dataclass(frozen=True)
class CustomFormat:
    """A validated administrator custom format mapping."""

    format_id: str
    pattern: "_rx.Pattern[str]"
    timing: dict[str, dict[str, object]]


def _validate_timing(timing: object) -> dict[str, dict[str, object]]:
    if timing is None:
        return {}
    if not isinstance(timing, dict):
        raise CustomFormatError("interrupted:custom_invalid")
    cleaned: dict[str, dict[str, object]] = {}
    for name, spec in timing.items():
        if name not in TIMING_GROUPS or not isinstance(spec, dict):
            raise CustomFormatError("interrupted:custom_invalid")
        unit = spec.get("unit")
        if unit not in ALLOWED_UNITS:
            raise CustomFormatError("interrupted:custom_invalid")
        multi = bool(spec.get("multi", False))
        if set(spec) - {"unit", "multi"}:
            raise CustomFormatError("interrupted:custom_invalid")
        cleaned[name] = {"unit": unit, "multi": multi}
    return cleaned


def load_spec(data: dict) -> CustomFormat:
    """Validate a parsed JSON mapping into a :class:`CustomFormat`."""
    if not isinstance(data, dict):
        raise CustomFormatError("interrupted:custom_invalid")
    format_id = data.get("format_id")
    pattern_text = data.get("pattern")
    if not isinstance(format_id, str) or not _FORMAT_ID_RE.match(format_id):
        raise CustomFormatError("interrupted:custom_invalid")
    if not isinstance(pattern_text, str) or not pattern_text:
        raise CustomFormatError("interrupted:custom_invalid")
    configured_cap = data.get("max_pattern_len", MAX_PATTERN_LEN)
    if isinstance(configured_cap, bool) or not isinstance(configured_cap, int):
        # Fail closed on wrong types (numeric strings, floats, containers):
        # silent coercion would let an absurd cap through.
        raise CustomFormatError("interrupted:custom_invalid")
    if configured_cap < 1 or len(pattern_text) > min(MAX_PATTERN_LEN, configured_cap):
        raise CustomFormatError("interrupted:custom_invalid")
    if data.get("time_format", "combined") != "combined":
        raise CustomFormatError("interrupted:custom_invalid")
    groups = _GROUP_RE.findall(pattern_text)
    if len(groups) != len(set(groups)):
        raise CustomFormatError("interrupted:custom_invalid")
    names = set(groups)
    if not REQUIRED_GROUPS.issubset(names) or not names.issubset(ALLOWED_GROUPS):
        raise CustomFormatError("interrupted:custom_invalid")
    # Every named-group body must be nesting-free and safe-shaped.
    # Parens inside character classes or escapes do not affect depth.
    for match in re.finditer(r"\(\?P<[A-Za-z_][A-Za-z0-9_]*>", pattern_text):
        start = match.end()
        depth = 1
        pos = start
        while pos < len(pattern_text) and depth > 0:
            char = pattern_text[pos]
            if char == "\\":
                pos += 2
                continue
            if char == "[":
                end = _skip_class(pattern_text, pos)
                if end is None:
                    raise CustomFormatError("interrupted:custom_invalid")
                pos = end
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            pos += 1
        if depth != 0:
            raise CustomFormatError("interrupted:custom_invalid")
        if not _check_body_safe(pattern_text[start : pos - 1]):
            raise CustomFormatError("interrupted:custom_invalid")
    try:
        compiled = _rx.compile(pattern_text)
    except (_rx.error, re.error):
        raise CustomFormatError("interrupted:custom_invalid") from None
    if compiled.groups != len(groups):
        # No unnamed capturing groups: keeps extraction positional-safe.
        raise CustomFormatError("interrupted:custom_invalid")
    timing = _validate_timing(data.get("timing"))
    for name in timing:
        if name not in names:
            raise CustomFormatError("interrupted:custom_invalid")
    return CustomFormat(format_id=format_id, pattern=compiled, timing=timing)


def load_spec_file(path: Path) -> CustomFormat:
    """Load and validate a custom-format JSON file (bounded size).

    At most ``MAX_SPEC_BYTES + 1`` bytes are ever read: an oversize file
    is rejected without buffering the whole file first.
    """
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_SPEC_BYTES + 1)
    except OSError:
        raise CustomFormatError("interrupted:custom_invalid") from None
    if len(raw) > MAX_SPEC_BYTES:
        raise CustomFormatError("interrupted:custom_invalid")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CustomFormatError("interrupted:custom_invalid") from None
    return load_spec(data)


def parse_custom_line(
    raw: bytes,
    *,
    spec: CustomFormat,
    source_id: str,
    hmac_key: bytes,
    line_number: int = 0,
    byte_offset: int = 0,
    file_dev: int = 0,
    file_ino: int = 0,
    limits=None,
):
    """Parse one line with a validated custom mapping (bounded, no eval)."""
    from app.ingestion.combined import (
        CombinedRecord,
        ExtendedMetadata,
        Limits,
        LineRejection,
        TimingInvalid,
        _excerpt,
        _normalize_host,
        _normalize_referer,
        _normalize_referer_path,
        _normalize_request,
        _normalize_time,
        normalize_timing,
        pseudonymize_client,
    )

    limits = limits or Limits()

    def reject(reason: str) -> LineRejection:
        return LineRejection(line_number, byte_offset, reason, _excerpt(raw, limits))

    if len(raw) > limits.max_line_bytes:
        return reject("oversized_line")
    try:
        line = raw.decode("utf-8")
    except UnicodeDecodeError:
        return reject("invalid_encoding")
    try:
        match = spec.pattern.match(line, timeout=CUSTOM_MATCH_TIMEOUT_S)
    except TimeoutError:
        # Proven per-operation budget (regex engine timeout, not a thread
        # timer): ambiguous input aborts here with a fixed code, never
        # exception text, and nothing keeps running afterwards.
        return reject("custom_timeout")
    if match is None:
        return reject("malformed_line")
    get = match.group
    # Length-cap every captured field before use (runtime budget).
    captured = {name: get(name) or "" for name in spec.pattern.groupindex}
    for name, value in captured.items():
        cap = limits.max_target_len if name in ("request", "referer") else 4096
        if len(value) > cap:
            return reject(
                f"oversized_{name}" if name in ("request", "referer") else "oversized_field"
            )
    request_text = captured.get("request") or ""
    if not request_text and "method" in captured:
        request_text = f"{captured.get('method', '')} {captured.get('target', '')}".strip()
    try:
        request = _normalize_request(request_text, limits)
    except ValueError as exc:
        return reject(
            str(exc) if str(exc) in ("empty_request", "oversized_target") else "malformed_request"
        )
    try:
        status = int(captured["status"])
    except ValueError:
        return reject("invalid_status")
    if not 100 <= status <= 599:
        return reject("invalid_status")
    size_text = captured.get("size", captured.get("bytes", "-")) or "-"
    bytes_sent = int(size_text) if size_text != "-" and size_text.isdigit() else None
    if size_text != "-" and bytes_sent is None:
        return reject("invalid_status")
    try:
        timestamp_utc, tz_offset_minutes = _normalize_time(captured["time"])
    except ValueError:
        return reject("invalid_time")
    referer = captured.get("referer", "-") or "-"
    user_agent = captured.get("user_agent", "-") or "-"
    if len(referer) > limits.max_referer_len:
        return reject("oversized_referer")
    normalized_ua: str | None = None
    if user_agent != "-":
        if len(user_agent) > limits.max_user_agent_len:
            return reject("oversized_user_agent")
        from app.ingestion.combined import _strip_controls, mask_secrets

        normalized_ua = mask_secrets(_strip_controls(user_agent)) or None
    try:
        referer_scheme, referer_path = _normalize_referer_path(referer, limits)
    except ValueError:
        return reject("oversized_referer")
    server_host: str | None = None
    if captured.get("vhost"):
        if captured["vhost"] == "-":
            # A "-" vhost is the missing-host marker, never a hostname;
            # absent hosts always pass host filtering.
            server_host = None
        else:
            try:
                server_host = _normalize_host(captured["vhost"], limits)
            except ValueError:
                return reject("invalid_host")
    cache_status = captured.get("cache") or None
    if cache_status == "-":
        cache_status = None
    mime_type = captured.get("mime") or None
    if mime_type == "-":
        mime_type = None
    tls_protocol = captured.get("tls") or None
    if tls_protocol == "-":
        tls_protocol = None
    request_time_ms: float | None = None
    upstream_time_ms: float | None = None
    upstream_count = 0
    for name in ("request_time", "upstream_time"):
        text = captured.get(name)
        if not text:
            continue
        unit = str(spec.timing.get(name, {}).get("unit", "s"))
        multi = bool(spec.timing.get(name, {}).get("multi", False))
        try:
            if text == "-":
                value: float | None = None
            elif multi:
                from app.ingestion.combined import _MULTI_SEP_RE

                total = 0.0
                parts = [p for p in _MULTI_SEP_RE.split(text.strip()) if p]
                if not parts:
                    raise TimingInvalid("empty timing")
                for part in parts:
                    piece = normalize_timing(part, unit)
                    assert piece is not None
                    total += piece
                    if not math.isfinite(total):
                        raise TimingInvalid("invalid upstream timing total: overflow")
                value = total
                if name == "upstream_time":
                    upstream_count = len(parts)
            else:
                value = normalize_timing(text, unit)
        except TimingInvalid:
            return reject("invalid_timing")
        if name == "request_time":
            request_time_ms = value
        else:
            upstream_time_ms = value
            if multi and value is not None and upstream_count == 0:
                upstream_count = 1
    from app.ingestion.combined import mask_secrets as _mask

    return CombinedRecord(
        source_id=source_id,
        format_id=spec.format_id,
        line_number=line_number,
        byte_offset=byte_offset,
        file_dev=file_dev,
        file_ino=file_ino,
        client_pseudonym=pseudonymize_client(captured["host"], hmac_key),
        timestamp_utc=timestamp_utc,
        tz_offset_minutes=tz_offset_minutes,
        request=request,
        status=status,
        bytes_sent=bytes_sent,
        referer_host=_normalize_referer(referer),
        user_agent=normalized_ua,
        duration_ms=None,
        extra=ExtendedMetadata(
            server_host=server_host,
            referer_scheme=referer_scheme,
            referer_path=referer_path,
            cache_status=_mask(cache_status).upper() if cache_status else None,
            request_time_ms=request_time_ms,
            upstream_time_ms=upstream_time_ms,
            upstream_count=upstream_count,
            mime_type=mime_type.lower() if mime_type else None,
            tls_protocol=tls_protocol,
        ),
    )

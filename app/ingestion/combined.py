"""NCSA Combined parser with explicit Nginx/Apache presets (T2).

Both presets share the Combined grammar
``%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"``. The presets
differ in escape handling: Apache escapes embedded quotes as ``\\"``,
while Nginx logs quoted fields raw. Normalization applies the privacy
defaults: UTC timestamps with the original numeric offset retained,
HMAC client pseudonyms, discarded query values, Referer minimization to
the host, secret-pattern masking, and ``duration_ms`` always ``None``
(plain Combined carries no timing; timing extensions are later work).

Raw lines are never retained: accepted records carry only normalized
fields, and rejections carry a short masked excerpt plus a reason code.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

# Explicit source presets. Unknown format IDs are rejected, never guessed.
NGINX_COMBINED = "nginx_combined"
APACHE_COMBINED = "apache_combined"
PRESETS = (NGINX_COMBINED, APACHE_COMBINED)


@dataclass(frozen=True)
class Limits:
    """Bounded-input contract. Oversized input is rejected, never truncated silently."""

    max_line_bytes: int = 65536
    max_target_len: int = 8192
    max_user_agent_len: int = 4096
    max_referer_len: int = 4096
    max_method_len: int = 32
    max_diagnostics: int = 20
    diagnostic_excerpt_len: int = 200


# A quoted field holds anything except a raw quote; backslash escapes
# (\" and \\) are consumed so they cannot end the field early.
def _quoted(name: str) -> str:
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


_COMBINED_RE = re.compile(
    r"(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\[\]]+)\]\s+"
    + _quoted("request")
    + r"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"
    + _quoted("referer")
    + r"\s+"
    + _quoted("user_agent")
    + r"\s*\Z"
)

_METHOD_RE = re.compile(r"^[\x21-\x7e]{1,32}$")
_VERSION_RE = re.compile(r"^HTTP/\d+(\.\d+)?$")
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Secret-bearing name=value fragments in paths, User-Agents and excerpts.
# The value stops at a delimiter so only the secret itself is masked.
_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|session[_-]?id|auth|bearer|jwt)([=:])[^/&;\s?#]*"
)

_REDACTED = "[REDACTED]"


def mask_secrets(text: str) -> str:
    """Replace secret-bearing values with a fixed marker."""
    return _SECRET_RE.sub(r"\1\2" + _REDACTED, text)


def _unescape(value: str) -> str:
    """Resolve backslash escapes (Apache preset)."""
    return re.sub(r"\\(.)", r"\1", value, flags=re.DOTALL)


def _strip_controls(value: str) -> str:
    """Drop C0/C1 control characters from attacker-controlled text."""
    return "".join(ch for ch in value if not (ord(ch) < 32 or ord(ch) == 127))


@dataclass(frozen=True)
class RequestLine:
    method: str
    target_path: str
    http_version: str | None


@dataclass(frozen=True)
class CombinedRecord:
    """One normalized Combined event. No raw line is retained."""

    source_id: str
    format_id: str
    line_number: int
    byte_offset: int
    file_dev: int
    file_ino: int
    client_pseudonym: str
    timestamp_utc: datetime
    tz_offset_minutes: int
    request: RequestLine
    status: int
    bytes_sent: int | None
    referer_host: str | None
    user_agent: str | None
    duration_ms: None = None


@dataclass(frozen=True)
class LineRejection:
    """A rejected line: position, reason code and a short masked excerpt."""

    line_number: int
    byte_offset: int
    reason: str
    excerpt: str


def pseudonymize_client(host: str, hmac_key: bytes) -> str:
    """HMAC-SHA256 pseudonym for a client address. Empty keys are refused."""
    if not hmac_key:
        raise ValueError("hmac_key must be non-empty")
    return hmac.new(hmac_key, host.encode("utf-8"), hashlib.sha256).hexdigest()


def _excerpt(raw: bytes, limits: Limits) -> str:
    """Bounded masked excerpt for diagnostics; never the full raw line."""
    text = raw[: limits.diagnostic_excerpt_len + 64].decode("utf-8", errors="replace")
    return mask_secrets(_strip_controls(text[: limits.diagnostic_excerpt_len]))


def _normalize_target(target: str) -> str:
    """Keep the path form: asterisk, absolute-URI path, or origin-form path."""
    if target == "*":
        return target
    if target.startswith(("http://", "https://")):
        path = urlsplit(target).path or "/"
    elif target.startswith("/"):
        path = target
    else:
        raise ValueError("not origin-form")
    return mask_secrets(path.split("?", 1)[0] or "/")


def _normalize_referer(value: str) -> str | None:
    """Minimize a Referer to its lowercase host; '-' and hosts absent -> None."""
    if value == "-":
        return None
    host = urlsplit(value).hostname
    return host.lower() if host else None


def parse_line(
    raw: bytes,
    *,
    source_id: str,
    format_id: str,
    hmac_key: bytes,
    line_number: int = 0,
    byte_offset: int = 0,
    file_dev: int = 0,
    file_ino: int = 0,
    limits: Limits | None = None,
) -> CombinedRecord | LineRejection:
    """Parse one raw Combined line into a normalized record or a rejection."""
    limits = limits or Limits()

    def reject(reason: str) -> LineRejection:
        return LineRejection(line_number, byte_offset, reason, _excerpt(raw, limits))

    if format_id not in PRESETS:
        raise ValueError(f"unknown format_id: {format_id!r}")
    if len(raw) > limits.max_line_bytes:
        return reject("oversized_line")
    try:
        line = raw.decode("utf-8")
    except UnicodeDecodeError:
        return reject("invalid_encoding")

    match = _COMBINED_RE.match(line)
    if match is None:
        return reject("malformed_line")
    if format_id == APACHE_COMBINED:
        parts = {
            name: _unescape(match.group(name)) for name in ("request", "referer", "user_agent")
        }
    else:
        parts = {name: match.group(name) for name in ("request", "referer", "user_agent")}

    # --- request line ---
    tokens = parts["request"].split()
    if len(tokens) < 2 or tokens == ["-"]:
        return reject("empty_request")
    if len(tokens) > 3:
        return reject("malformed_request")
    method = tokens[0]
    if len(method) > limits.max_method_len or not _METHOD_RE.match(method):
        return reject("malformed_request")
    version: str | None = None
    if len(tokens) == 3:
        if not _VERSION_RE.match(tokens[2]):
            return reject("malformed_request")
        version = tokens[2]
    target = tokens[1]
    if len(target) > limits.max_target_len:
        return reject("oversized_target")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        return reject("malformed_request")
    try:
        path = _normalize_target(target)
    except ValueError:
        return reject("malformed_request")

    # --- status / bytes ---
    status = int(match.group("status"))
    if not 100 <= status <= 599:
        return reject("invalid_status")
    size = match.group("size")
    bytes_sent = int(size) if size != "-" else None

    # --- timestamp (UTC normalized, original offset retained) ---
    try:
        moment = datetime.strptime(match.group("time"), _TIME_FORMAT)
    except ValueError:
        return reject("invalid_time")
    offset = moment.utcoffset()
    assert offset is not None  # %z always yields an aware datetime
    timestamp_utc = moment.astimezone(UTC)
    tz_offset_minutes = int(offset.total_seconds() // 60)

    # --- referer / user-agent ---
    referer = parts["referer"]
    if len(referer) > limits.max_referer_len:
        return reject("oversized_referer")
    user_agent = parts["user_agent"]
    if user_agent == "-":
        normalized_ua: str | None = None
    else:
        if len(user_agent) > limits.max_user_agent_len:
            return reject("oversized_user_agent")
        normalized_ua = mask_secrets(_strip_controls(user_agent)) or None

    return CombinedRecord(
        source_id=source_id,
        format_id=format_id,
        line_number=line_number,
        byte_offset=byte_offset,
        file_dev=file_dev,
        file_ino=file_ino,
        client_pseudonym=pseudonymize_client(match.group("host"), hmac_key),
        timestamp_utc=timestamp_utc,
        tz_offset_minutes=tz_offset_minutes,
        request=RequestLine(method=method, target_path=path, http_version=version),
        status=status,
        bytes_sent=bytes_sent,
        referer_host=_normalize_referer(referer),
        user_agent=normalized_ua,
        duration_ms=None,
    )

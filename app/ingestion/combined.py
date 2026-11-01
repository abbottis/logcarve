"""NCSA parsers with T1a parity presets (gzip/rotation follow in later slices).

Presets
-------

``nginx_combined`` / ``apache_combined``
    NCSA Combined grammar
    ``%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"``.
    Apache resolves backslash escapes (``\\"``); Nginx keeps raw fields.
``common``
    Common Log Format (CLF): ``%h %l %u %t "%r" %>s %b`` — no Referer or
    User-Agent. A Combined line is never mislabelled Common and vice versa:
    the grammars are disjoint by construction.
``apache_vhost_combined``
    Apache vhost Combined: ``%v`` (server hostname) followed by Combined.
``nginx_extended``
    Nginx Extended: Combined followed by six well-defined fields::

        <server_host> <combined...> <cache> <request_time> <mime> <tls> "<upstream_time>"

    ``cache`` is ``$upstream_cache_status`` (``-`` when absent),
    ``request_time`` is ``$request_time`` in seconds (``-`` when absent),
    ``mime`` is ``$sent_http_content_type`` (``type/subtype``, optional
    ``;params`` without spaces; ``-`` when absent), ``tls`` is
    ``$ssl_protocol`` (``-`` when absent), and ``upstream_time`` is the
    quoted ``$upstream_response_time`` in seconds (``-`` when absent, or a
    comma/colon/space separated multi-value list that is summed).

Normalization applies the privacy defaults: UTC timestamps with the
original numeric offset retained, HMAC pseudonyms, discarded query values,
Referer minimization (host plus a query/credential/secret-free path),
secret-pattern masking, and ``duration_ms`` stays ``None`` on records
without measured timing. Measured timings normalize to milliseconds;
absent timing is ``None``, never ``0``; present-but-invalid timing rejects
the line with ``invalid_timing``.

Raw lines are never retained: accepted records carry only normalized
fields, and rejections carry a short masked excerpt plus a reason code.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

# Explicit source presets. Unknown format IDs are rejected, never guessed.
NGINX_COMBINED = "nginx_combined"
APACHE_COMBINED = "apache_combined"
COMMON = "common"
APACHE_VHOST_COMBINED = "apache_vhost_combined"
NGINX_EXTENDED = "nginx_extended"
# ``auto`` resolves per file through sampled autodetect; ``custom`` resolves
# through a validated administrator mapping. Neither is a parse grammar.
AUTO = "auto"
CUSTOM = "custom"
PRESETS = (NGINX_COMBINED, APACHE_COMBINED)
T1A_PRESETS = (COMMON, APACHE_VHOST_COMBINED, NGINX_EXTENDED)
RESOLVABLE_FORMATS = PRESETS + T1A_PRESETS + (AUTO, CUSTOM)


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
    max_host_len: int = 253
    max_mime_len: int = 128


# A quoted field holds anything except a raw quote; backslash escapes
# (\" and \\) are consumed so they cannot end the field early.
def _quoted(name: str) -> str:
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


_COMBINED_BODY = (
    r"(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\[\]]+)\]\s+" + _quoted("request") + r"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)"
)

_COMBINED_RE = re.compile(
    _COMBINED_BODY + r"\s+" + _quoted("referer") + r"\s+" + _quoted("user_agent") + r"\s*\Z"
)

_COMMON_RE = re.compile(_COMBINED_BODY + r"\s*\Z")

_VHOST_RE = re.compile(
    r"(?P<vhost>\S+)\s+"
    + _COMBINED_BODY
    + r"\s+"
    + _quoted("referer")
    + r"\s+"
    + _quoted("user_agent")
    + r"\s*\Z"
)

_EXTENDED_RE = re.compile(
    r"(?P<vhost>\S+)\s+"
    + _COMBINED_BODY
    + r"\s+"
    + _quoted("referer")
    + r"\s+"
    + _quoted("user_agent")
    + r"\s+(?P<cache>\S+)\s+(?P<request_time>\S+)\s+(?P<mime>\S+)\s+(?P<tls>\S+)\s+"
    + _quoted("upstream_time")
    + r"\s*\Z"
)

_PRESET_RES = {
    NGINX_COMBINED: _COMBINED_RE,
    APACHE_COMBINED: _COMBINED_RE,
    COMMON: _COMMON_RE,
    APACHE_VHOST_COMBINED: _VHOST_RE,
    NGINX_EXTENDED: _EXTENDED_RE,
}

_METHOD_RE = re.compile(r"^[\x21-\x7e]{1,32}$")
_VERSION_RE = re.compile(r"^HTTP/\d+(\.\d+)?$")
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
_HOST_RE = re.compile(r"^\S{1,253}$")
_CACHE_RE = re.compile(r"^[A-Za-z_]{1,32}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_MIME_RE = re.compile(r"^[^/\s;]{1,64}/[^;\s]{1,64}$")
_NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_MULTI_SEP_RE = re.compile(r"[,\s:;]+")
_KNOWN_TLS = frozenset({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv2", "SSLv3"})

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


class TimingInvalid(ValueError):
    """A present timing value cannot be interpreted under its declared unit."""


def normalize_seconds_to_ms(value: str) -> float | None:
    """Normalize a seconds timing (Nginx ``$request_time``) to milliseconds.

    ``-`` means absent and yields ``None`` (never ``0``). Anything else must
    be a plain decimal number; anything unparseable raises :class:`TimingInvalid`.
    """
    if value == "-":
        return None
    if not _NUMBER_RE.match(value):
        raise TimingInvalid(f"invalid seconds timing: {value[:32]!r}")
    return float(value) * 1000.0


def normalize_multi_seconds_to_ms(value: str) -> tuple[float | None, int]:
    """Normalize a quoted upstream timing to ``(total_ms, component_count)``.

    ``-`` means absent and yields ``(None, 0)``. A comma/colon/space
    separated multi-value list (Nginx ``$upstream_response_time`` with
    several upstreams tried) is summed explicitly and the component count
    is returned alongside; any unparseable component raises
    :class:`TimingInvalid`.
    """
    if value == "-":
        return None, 0
    parts = [item for item in _MULTI_SEP_RE.split(value.strip()) if item]
    if not parts:
        raise TimingInvalid("empty upstream timing")
    total = 0.0
    for part in parts:
        if not _NUMBER_RE.match(part):
            raise TimingInvalid(f"invalid upstream timing component: {part[:32]!r}")
        total += float(part) * 1000.0
    return total, len(parts)


def normalize_timing(value: str, unit: str) -> float | None:
    """Normalize a custom timing value under an explicit unit to milliseconds.

    ``unit`` is one of ``s`` (seconds), ``ms`` (milliseconds) or ``us``
    (microseconds, Apache ``%D``). ``-`` means absent (``None``). Unknown
    units raise :class:`TimingInvalid` so misconfiguration fails closed.
    """
    if value == "-":
        return None
    if unit not in ("s", "ms", "us"):
        raise TimingInvalid(f"unknown timing unit: {unit!r}")
    if not _NUMBER_RE.match(value):
        raise TimingInvalid(f"invalid timing value: {value[:32]!r}")
    number = float(value)
    if unit == "s":
        return number * 1000.0
    if unit == "us":
        return number / 1000.0
    return number


@dataclass(frozen=True)
class RequestLine:
    method: str
    target_path: str
    http_version: str | None


@dataclass(frozen=True)
class ExtendedMetadata:
    """Normalized measured/enrichment metadata for one record.

    All fields are nullable: absent stays ``None`` (never ``0`` or ``""``).
    Present-but-invalid values reject the line instead of landing here, so
    ``None`` always means absent. T1b persists these without reparsing.
    """

    server_host: str | None = None
    referer_scheme: str | None = None
    referer_path: str | None = None
    cache_status: str | None = None
    request_time_ms: float | None = None
    upstream_time_ms: float | None = None
    upstream_count: int = 0
    mime_type: str | None = None
    tls_protocol: str | None = None


@dataclass(frozen=True)
class CombinedRecord:
    """One normalized event. Raw lines are never retained."""

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
    extra: ExtendedMetadata = field(default_factory=ExtendedMetadata)


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


def _normalize_referer_path(value: str, limits: Limits) -> tuple[str | None, str | None]:
    """Minimize a Referer to ``(scheme, path)`` without query/credentials/secrets.

    The scheme is kept only for ``http``/``https``; anything else yields
    ``None`` for the scheme while the path is still extracted. Userinfo is
    dropped by construction (only ``path`` is read). ``-`` yields
    ``(None, None)``.
    """
    if value == "-":
        return None, None
    if len(value) > limits.max_referer_len:
        raise ValueError("oversized_referer")
    try:
        parts = urlsplit(value)
    except ValueError:
        return None, None
    scheme = parts.scheme.lower() or None
    if scheme not in ("http", "https"):
        scheme = None
    if not parts.hostname and not parts.path:
        return scheme, None
    path = mask_secrets(parts.path or "/").split("?", 1)[0] or "/"
    return scheme, path[: limits.max_target_len]


def _normalize_host(value: str, limits: Limits) -> str:
    """Lowercase a server/vhost hostname; rejects overlong or blank hosts."""
    host = value.strip().lower()
    if not host or len(host) > limits.max_host_len or not _HOST_RE.match(host):
        raise ValueError("invalid_host")
    return host


def _normalize_cache(value: str) -> str | None:
    if value == "-":
        return None
    if not _CACHE_RE.match(value):
        raise ValueError("invalid_cache")
    return value.upper()


def _normalize_tls(value: str) -> str | None:
    if value == "-":
        return None
    if not _TOKEN_RE.match(value):
        raise ValueError("invalid_tls")
    return value


def _normalize_mime(value: str, limits: Limits) -> str | None:
    if value == "-":
        return None
    if len(value) > limits.max_mime_len:
        raise ValueError("invalid_mime")
    media = value.split(";", 1)[0].strip().lower()
    if not _MIME_RE.match(media):
        raise ValueError("invalid_mime")
    return media


def _normalize_time(value: str) -> tuple[datetime, int]:
    try:
        moment = datetime.strptime(value, _TIME_FORMAT)
    except ValueError as exc:
        raise ValueError("invalid_time") from exc
    offset = moment.utcoffset()
    assert offset is not None  # %z always yields an aware datetime
    return moment.astimezone(UTC), int(offset.total_seconds() // 60)


def _normalize_request(request: str, limits: Limits) -> RequestLine:
    tokens = request.split()
    if len(tokens) < 2 or tokens == ["-"]:
        raise ValueError("empty_request")
    if len(tokens) > 3:
        raise ValueError("malformed_request")
    method = tokens[0]
    if len(method) > limits.max_method_len or not _METHOD_RE.match(method):
        raise ValueError("malformed_request")
    version: str | None = None
    if len(tokens) == 3:
        if not _VERSION_RE.match(tokens[2]):
            raise ValueError("malformed_request")
        version = tokens[2]
    target = tokens[1]
    if len(target) > limits.max_target_len:
        raise ValueError("oversized_target")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        raise ValueError("malformed_request")
    try:
        path = _normalize_target(target)
    except ValueError as exc:
        raise ValueError("malformed_request") from exc
    return RequestLine(method=method, target_path=path, http_version=version)


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
    """Parse one raw log line into a normalized record or a rejection."""
    limits = limits or Limits()

    def reject(reason: str) -> LineRejection:
        return LineRejection(line_number, byte_offset, reason, _excerpt(raw, limits))

    try:
        pattern = _PRESET_RES[format_id]
    except KeyError:
        raise ValueError(f"unknown format_id: {format_id!r}") from None
    if format_id in (AUTO, CUSTOM):
        raise ValueError(f"format_id {format_id!r} must be resolved before parsing")
    if len(raw) > limits.max_line_bytes:
        return reject("oversized_line")
    try:
        line = raw.decode("utf-8")
    except UnicodeDecodeError:
        return reject("invalid_encoding")

    match = pattern.match(line)
    if match is None:
        return reject("malformed_line")
    if format_id in (APACHE_COMBINED, APACHE_VHOST_COMBINED):
        parts = {
            name: _unescape(match.group(name)) for name in ("request", "referer", "user_agent")
        }
    else:
        get = match.group
        names = ("request", "referer", "user_agent") if format_id != COMMON else ("request",)
        parts = {name: get(name) for name in names}

    # --- request line ---
    try:
        request = _normalize_request(parts["request"], limits)
    except ValueError as exc:
        reason = str(exc)
        if reason not in (
            "empty_request",
            "malformed_request",
            "oversized_target",
        ):
            reason = "malformed_request"
        return reject(reason)

    # --- status / bytes ---
    status = int(match.group("status"))
    if not 100 <= status <= 599:
        return reject("invalid_status")
    size = match.group("size")
    bytes_sent = int(size) if size != "-" else None

    # --- timestamp (UTC normalized, original offset retained) ---
    try:
        timestamp_utc, tz_offset_minutes = _normalize_time(match.group("time"))
    except ValueError:
        return reject("invalid_time")

    # --- referer / user-agent ---
    referer = parts.get("referer", "-")
    if len(referer) > limits.max_referer_len:
        return reject("oversized_referer")
    user_agent = parts.get("user_agent", "-")
    if user_agent == "-":
        normalized_ua: str | None = None
    else:
        if len(user_agent) > limits.max_user_agent_len:
            return reject("oversized_user_agent")
        normalized_ua = mask_secrets(_strip_controls(user_agent)) or None
    try:
        referer_scheme, referer_path = _normalize_referer_path(referer, limits)
    except ValueError:
        return reject("oversized_referer")

    # --- host / measured fields (vhost + extended presets) ---
    server_host: str | None = None
    cache_status: str | None = None
    request_time_ms: float | None = None
    upstream_time_ms: float | None = None
    upstream_count = 0
    mime_type: str | None = None
    tls_protocol: str | None = None
    if format_id in (APACHE_VHOST_COMBINED, NGINX_EXTENDED):
        try:
            server_host = _normalize_host(match.group("vhost"), limits)
        except ValueError:
            return reject("invalid_host")
    if format_id == NGINX_EXTENDED:
        try:
            cache_status = _normalize_cache(match.group("cache"))
        except ValueError:
            return reject("invalid_cache")
        try:
            request_time_ms = normalize_seconds_to_ms(match.group("request_time"))
        except TimingInvalid:
            return reject("invalid_timing")
        try:
            mime_type = _normalize_mime(match.group("mime"), limits)
        except ValueError:
            return reject("invalid_mime")
        try:
            tls_protocol = _normalize_tls(match.group("tls"))
        except ValueError:
            return reject("invalid_tls")
        try:
            upstream_time_ms, upstream_count = normalize_multi_seconds_to_ms(
                match.group("upstream_time")
            )
        except TimingInvalid:
            return reject("invalid_timing")

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
            cache_status=cache_status,
            request_time_ms=request_time_ms,
            upstream_time_ms=upstream_time_ms,
            upstream_count=upstream_count,
            mime_type=mime_type,
            tls_protocol=tls_protocol,
        ),
    )

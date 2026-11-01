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
    Nginx Extended: Combined followed by six trailing fields AFTER the
    User-Agent (LogWerk NginxExtended preset)::

        <combined...> <server_host> <cache> <request_time> <mime> <tls> "<upstream_time>"

    ``server_host`` is the trailing ``$host`` (``-`` means absent, never
    a name), ``cache`` is ``$upstream_cache_status`` (``-`` when absent),
    ``request_time`` is ``$request_time`` in seconds (``-`` when absent),
    ``mime`` is ``$sent_http_content_type`` (``type/subtype``, optional
    ``;params`` possibly with one embedded space such as
    ``text/html; charset=utf-8``; ``-`` when absent), ``tls`` is
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
fields, and rejections carry a fixed withheld marker plus a reason code.
No attacker-controlled bytes (original IPs, query values, paths,
User-Agents, Referers) ever land in diagnostics, reports, errors or logs.
"""

import hashlib
import hmac
import ipaddress
import math
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
    """Bounded-input contract. Oversized input is rejected, never truncated silently.

    Values are validated on construction: sizes must be positive integers
    (bools rejected) within a plausible ceiling so an absurd cap cannot
    turn a bounded buffer into an unbounded allocation.
    """

    max_line_bytes: int = 65536
    max_target_len: int = 8192
    max_user_agent_len: int = 4096
    max_referer_len: int = 4096
    max_method_len: int = 32
    max_diagnostics: int = 20
    diagnostic_excerpt_len: int = 200
    max_host_len: int = 253
    max_mime_len: int = 128

    def __post_init__(self) -> None:
        for name in (
            "max_line_bytes",
            "max_target_len",
            "max_user_agent_len",
            "max_referer_len",
            "max_method_len",
            "diagnostic_excerpt_len",
            "max_host_len",
            "max_mime_len",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**26:
                raise ValueError(f"{name} must be an integer in 1..2**26")
        if (
            isinstance(self.max_diagnostics, bool)
            or not isinstance(self.max_diagnostics, int)
            or not 0 <= self.max_diagnostics <= 1_000_000
        ):
            raise ValueError("max_diagnostics must be an integer in 0..1000000")


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
    _COMBINED_BODY
    + r"\s+"
    + _quoted("referer")
    + r"\s+"
    + _quoted("user_agent")
    # Trailing LogWerk NginxExtended fields: $host $upstream_cache_status
    # $request_time $sent_http_content_type $ssl_protocol
    # "$upstream_response_time". A leading vhost is Apache vhost Combined,
    # never this preset. The MIME field is the full
    # $sent_http_content_type value: a media type plus any number of
    # "; param=..." segments (e.g. "text/html; charset=utf-8;
    # version=1.0"), so it may contain spaces. The lazy match plus the
    # trailing TLS/upstream anchors pin the split: TLS is the last
    # whitespace-separated token before the quoted upstream time.
    + r"\s+(?P<vhost>\S+)\s+(?P<cache>\S+)\s+(?P<request_time>\S+)"
    + r"\s+(?P<mime>[^\"]+?)\s+(?P<tls>\S+)\s+"
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


def _checked_ms(number: float, factor: float, original: str) -> float:
    """Scale a parsed timing and require a finite nonnegative result.

    Zero is a valid measurement; negative, NaN, infinite and overflowing
    values reject the line instead of persisting ``-1000``, ``inf`` or a
    JSON-hostile NaN.
    """
    result = number * factor
    if not math.isfinite(result) or result < 0:
        raise TimingInvalid(f"invalid timing value: {original[:32]!r}")
    return result


def normalize_seconds_to_ms(value: str) -> float | None:
    """Normalize a seconds timing (Nginx ``$request_time``) to milliseconds.

    ``-`` means absent and yields ``None`` (never ``0``). Anything else must
    be a plain nonnegative decimal number with a finite millisecond value;
    anything unparseable, negative or overflowing raises
    :class:`TimingInvalid`.
    """
    if value == "-":
        return None
    if not _NUMBER_RE.match(value):
        raise TimingInvalid(f"invalid seconds timing: {value[:32]!r}")
    return _checked_ms(float(value), 1000.0, value)


def normalize_multi_seconds_to_ms(value: str) -> tuple[float | None, int | None]:
    """Normalize a quoted upstream timing to ``(total_ms, component_count)``.

    ``-`` means absent and yields ``(None, None)``: no components were
    logged, so no count is inferred. A comma/colon/space separated
    multi-value list (Nginx ``$upstream_response_time`` with several
    upstreams tried) is summed explicitly and the component count is
    returned alongside.

    A ``-`` component inside an otherwise valid list (for example
    ``"0.100, -"``) means one upstream leg logged no timing: the
    complete total is then unavailable and yields ``(None, None)`` --
    the missing leg is never turned into zero, and the event itself
    stays valid so a separately measured request duration on the same
    line is preserved. Truly unparseable, negative or overflowing
    components still raise :class:`TimingInvalid` and reject the line.
    """
    if value == "-":
        return None, None
    parts = [item for item in _MULTI_SEP_RE.split(value.strip()) if item]
    if not parts:
        raise TimingInvalid("empty upstream timing")
    if any(part == "-" for part in parts):
        # Partial upstream timing: at least one leg is missing, so no
        # complete total and no component count can be reported.
        return None, None
    total = 0.0
    for part in parts:
        if not _NUMBER_RE.match(part):
            raise TimingInvalid(f"invalid upstream timing component: {part[:32]!r}")
        component = float(part) * 1000.0
        if not math.isfinite(component) or component < 0:
            raise TimingInvalid(f"invalid upstream timing component: {part[:32]!r}")
        total += component
        if not math.isfinite(total):
            raise TimingInvalid("invalid upstream timing total: overflow")
    return total, len(parts)


def normalize_timing(value: str, unit: str) -> float | None:
    """Normalize a custom timing value under an explicit unit to milliseconds.

    ``unit`` is one of ``s`` (seconds), ``ms`` (milliseconds) or ``us``
    (microseconds, Apache ``%D``). ``-`` means absent (``None``); ``0``
    stays a valid zero measurement. Unknown units, negative values and
    non-finite results raise :class:`TimingInvalid` so misconfiguration
    fails closed.
    """
    if value == "-":
        return None
    if unit not in ("s", "ms", "us"):
        raise TimingInvalid(f"unknown timing unit: {unit!r}")
    if not _NUMBER_RE.match(value):
        raise TimingInvalid(f"invalid timing value: {value[:32]!r}")
    number = float(value)
    if unit == "s":
        return _checked_ms(number, 1000.0, value)
    if unit == "us":
        return _checked_ms(number, 1 / 1000.0, value)
    return _checked_ms(number, 1.0, value)


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
    ``None`` always means absent -- including ``upstream_count``, which is
    the number of upstream timing components only when an upstream timing
    was actually logged. T1b persists these without reparsing.
    """

    server_host: str | None = None
    referer_scheme: str | None = None
    referer_path: str | None = None
    cache_status: str | None = None
    request_time_ms: float | None = None
    upstream_time_ms: float | None = None
    upstream_count: int | None = None
    mime_type: str | None = None
    tls_protocol: str | None = None


#: Explicit parser/normalization policy version for reproducibility.
#: Persisted per enriched row (legacy rows stay NULL); a policy change
#: re-enriches on reprocess. Custom mappings additionally carry a
#: definition fingerprint (see :func:`enrichment_policy`); raw custom
#: configuration and secrets are never persisted.
PARSER_POLICY_VERSION = "t1b.1"


def enrichment_policy(format_id: str, custom_format: object = None) -> str:
    """Policy tag persisted with enrichment metadata for reproducibility."""
    if custom_format is None:
        return PARSER_POLICY_VERSION
    import hashlib as _hashlib
    import json as _json

    digest = _hashlib.sha256()
    digest.update(str(getattr(custom_format, "format_id", format_id)).encode("utf-8"))
    pattern = getattr(custom_format, "pattern", None)
    source = getattr(pattern, "pattern", "")
    digest.update(b"\x00" + str(source).encode("utf-8"))
    timing = getattr(custom_format, "timing", {})
    digest.update(b"\x00" + _json.dumps(timing, sort_keys=True, default=str).encode("utf-8"))
    return f"{PARSER_POLICY_VERSION}+custom:{digest.hexdigest()[:16]}"


class CapturedOriginal:
    """Transient SecretStr-safe capture of one validated original address.

    Deliberately NOT a dataclass: :func:`dataclasses.asdict` on a
    dataclass would emit its fields as plaintext (``{'_plaintext':
    '192.0.2.44'}``), including nested inside another dataclass. As a
    plain slotted class holding a Pydantic ``SecretStr``, ``asdict``
    raises ``TypeError`` on a bare capture, and nested ``asdict``/
    ``deepcopy``/``pickle`` paths keep only a withheld marker -- never
    the address text. The plaintext is revealed solely through
    :meth:`reveal`, called immediately inside proven
    encryption/admin-private functions. ``repr``/``str`` (and therefore
    tuples, lists, logs and exception text carrying this value) show
    only a fixed withheld marker, and the value is not
    JSON-serializable. Use ``capture_original=True`` parse paths only
    to route into the encrypted private channel.
    """

    __slots__ = ("_secret",)

    def __init__(self, plaintext: str) -> None:
        from pydantic import SecretStr as _SecretStr

        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("captured address must be a non-empty string")
        self._secret = _SecretStr(plaintext)

    def reveal(self) -> str:
        """Return the captured address text for immediate encryption."""
        return self._secret.get_secret_value()

    def __repr__(self) -> str:
        return "CapturedOriginal(<withheld>)"

    def __str__(self) -> str:
        return "CapturedOriginal(<withheld>)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CapturedOriginal):
            return NotImplemented
        return self.reveal() == other.reveal()

    def __hash__(self) -> int:
        return hash(self.reveal())

    def __copy__(self, memo: object = None) -> "CapturedOriginal":
        return CapturedOriginal(self.reveal())

    def __deepcopy__(self, memo: object = None) -> "CapturedOriginal":
        return CapturedOriginal(self.reveal())

    def __getstate__(self) -> dict[str, str]:
        # Pickle/copyreg paths keep only the withheld marker, never the
        # address text. Encryption inputs use the live object directly.
        return {"withheld": "CapturedOriginal(<withheld>)"}

    def __setstate__(self, state: object) -> None:
        raise ValueError("CapturedOriginal cannot be restored from serialized state")


def validate_original_ip(text: str) -> str | None:
    """Return ``text`` when it is a valid IPv4/IPv6 address, else ``None``.

    Validation is transient and ingestion-local (no storage/crypto
    dependency): the textual form is preserved exactly (including IPv6
    spellings) so the legacy HMAC input stays byte-exact.
    """
    if not isinstance(text, str) or not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


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
    """A rejected line: position, reason code and a fixed withheld marker.

    ``excerpt`` never carries attacker-controlled bytes: it is derived
    only from the allowlisted reason code, so unparseable, invalid-UTF8,
    oversized, custom-timeout, IPv4/IPv6 or query/secret-bearing lines
    cannot leak original addresses or query values through diagnostics,
    CLI reports, exceptions or logs. Bounded counters (by reason) plus
    line/offset positions keep diagnostics useful.
    """

    line_number: int
    byte_offset: int
    reason: str
    excerpt: str


def pseudonymize_client(host: str, hmac_key: bytes) -> str:
    """HMAC-SHA256 pseudonym for a client address. Empty keys are refused."""
    if not hmac_key:
        raise ValueError("hmac_key must be non-empty")
    return hmac.new(hmac_key, host.encode("utf-8"), hashlib.sha256).hexdigest()


WITHHELD_EXCERPT = "<withheld>"

#: Allowlisted rejection reasons that may appear in diagnostics. The
#: withheld marker is derived only from these codes, never from raw input.
_REJECTION_REASONS = frozenset(
    {
        "malformed_line",
        "malformed_request",
        "empty_request",
        "oversized_line",
        "oversized_target",
        "oversized_referer",
        "oversized_user_agent",
        "oversized_field",
        "invalid_status",
        "invalid_time",
        "invalid_encoding",
        "invalid_host",
        "invalid_cache",
        "invalid_mime",
        "invalid_tls",
        "invalid_timing",
        "custom_timeout",
    }
)


def _excerpt(reason: str, limits: Limits | None = None) -> str:
    """Fixed withheld marker for diagnostics; never attacker-controlled bytes.

    The marker is derived only from the allowlisted reason code (plus the
    static ``<withheld>`` prefix space): rejected raw lines — including
    short lines that a truncation scheme would return almost in full,
    malformed lines, invalid-UTF8 bytes, oversized lines, custom timeouts
    and IPv4/IPv6/query/secret-bearing input — cannot leak original
    addresses or query values through this channel. ``limits`` is accepted
    for call-site compatibility and ignored.
    """
    _ = limits
    code = reason if reason in _REJECTION_REASONS else "rejected"
    return f"{WITHHELD_EXCERPT}:{code}"


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


def _matched_original_host(host_text: str) -> CapturedOriginal | None:
    """Validated transient original address from the matched host group.

    Returns a :class:`CapturedOriginal` wrapping the exact textual host
    (IPv6 spellings preserved byte-exact for the legacy HMAC input) when
    it is a valid IPv4/IPv6 address, else ``None``. The value is
    transient: callers must route it only into the encrypted private
    channel, never into routine fields or diagnostics. Never carried out
    with a rejection or foreign-host skip.
    """
    validated = validate_original_ip(host_text)
    if validated is None:
        return None
    return CapturedOriginal(validated)


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
    capture_original: bool = False,
) -> (
    CombinedRecord | LineRejection | tuple[CombinedRecord | LineRejection, CapturedOriginal | None]
):
    """Parse one raw log line into a normalized record or a rejection.

    With ``capture_original=False`` (default) returns just the item and
    stays fully compatible. With ``capture_original=True`` returns
    ``(item, original_or_None)`` where the original is a
    :class:`CapturedOriginal` transiently captured from the same match
    the HMAC pseudonym derives from (``None`` for rejections: no
    original is ever carried out with a rejection or foreign-host
    skip). The side channel may carry ciphertext; routine plaintext
    fields never carry originals.
    """
    limits = limits or Limits()

    def reject(reason: str) -> LineRejection | tuple[LineRejection, None]:
        item = LineRejection(line_number, byte_offset, reason, _excerpt(reason, limits))
        if capture_original:
            return (item, None)
        return item

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
    upstream_count: int | None = None
    mime_type: str | None = None
    tls_protocol: str | None = None
    if format_id in (APACHE_VHOST_COMBINED, NGINX_EXTENDED):
        raw_host = match.group("vhost")
        if raw_host == "-":
            # Trailing "-" is the missing-host marker (extended null rows),
            # not a hostname; absent hosts always pass host filtering.
            server_host = None
        else:
            try:
                server_host = _normalize_host(raw_host, limits)
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

    host_text = match.group("host")
    record = CombinedRecord(
        source_id=source_id,
        format_id=format_id,
        line_number=line_number,
        byte_offset=byte_offset,
        file_dev=file_dev,
        file_ino=file_ino,
        client_pseudonym=pseudonymize_client(host_text, hmac_key),
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
    if not capture_original:
        return record
    return (record, _matched_original_host(host_text))

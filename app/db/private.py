"""Encrypted original-IP store for local-admin display (T1b, PAR-02).

Original client addresses are persisted ONLY here, encrypted with a
separate server key, and read back ONLY through the explicit private
reader below. They never flow through routine DTOs, dataclass ``asdict``
or ``repr`` output, CLI reports, the external API, shared analytics,
model tools, exports, error messages or logs. The capture side channel
may carry ciphertext (nonce + ciphertext blobs bound to a request);
routine plaintext fields never carry originals.

Cryptography: AES-256-GCM from the proven ``cryptography`` package
(``AESGCM``; primary docs at
https://github.com/pyca/cryptography/blob/main/docs/hazmat/primitives/aead.rst).
Every encryption uses a fresh random 12-byte nonce, never reused. The
site/source/event identity (site id, source id, file fingerprint, byte
offset) is bound as associated data (AAD): ciphertext swapped onto
another event or site fails closed with a fixed unavailable code.
``InvalidTag`` always means fail closed: no plaintext/ciphertext
fallback, and ordinary analytics keep working without a key.

Key separation: the key comes ONLY from the ``ORIGINAL_IP_KEY``
environment variable (or an explicitly passed equivalent). It is never
``SESSION_SECRET``, ``HMAC_KEY`` or ``MODEL_API_KEY``; those values are
rejected outright. The key is ``SecretStr``-safe, never stored in the
database, Git, UI output or logs, and key validation never echoes input.
Missing, invalid, wrong or tampered keys yield fixed unavailable codes.
"""

import base64
import binascii
import ipaddress
import os
import re
import sqlite3
from datetime import UTC, datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

IP_KEY_ENV = "ORIGINAL_IP_KEY"
NONCE_BYTES = 12
KEY_BYTES = 32
AAD_VERSION = b"logcarve-ip-v1"

UNAVAILABLE_NO_KEY = "private_unavailable:no_key"
UNAVAILABLE_INVALID_KEY = "private_unavailable:invalid_key"
UNAVAILABLE_DECRYPT_FAILED = "private_unavailable:decrypt_failed"
UNAVAILABLE_NOT_STORED = "private_unavailable:not_stored"

#: Keys that must never serve as the original-IP key (fail closed).
_FORBIDDEN_KEY_NAMES = ("SESSION_SECRET", "HMAC_KEY", "MODEL_API_KEY", "META_API_KEY")

IP_DISPLAY_FULL = "full"
IP_DISPLAY_SUFFIX_MASK = "suffix_mask"
IP_DISPLAY_PSEUDONYM_ONLY = "pseudonym_only"
IP_DISPLAY_MODES = (IP_DISPLAY_FULL, IP_DISPLAY_SUFFIX_MASK, IP_DISPLAY_PSEUDONYM_ONLY)
_IP_DISPLAY_SETTING_KEY = "ip_display_mode"


class PrivateUnavailable(Exception):
    """Original-IP access is unavailable; fixed code only, never key material."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _secret_value(value: object) -> str | bytes:
    """Unwrap ``SecretStr``-like values without ever logging them."""
    get_secret = getattr(value, "get_secret_value", None)
    if callable(get_secret):
        return get_secret()
    return value  # type: ignore[return-value]


_HEX_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_B64STD_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_B64URL_RE = re.compile(r"[A-Za-z0-9\-_]*={0,2}\Z")


def parse_ip_key(value: object) -> bytes:
    """Parse and validate an original-IP key; fail closed with fixed codes.

    Accepted forms all decode to exactly 32 raw bytes: raw 32-byte
    input, exactly 64 hex characters (no embedded whitespace: ``str``
    ``strip``/``fromhex`` leniency is not relied on), or base64
    (standard or URL-safe alphabet, documented padded or unpadded forms)
    decoding to 32 bytes. Only surrounding newlines (``\\r``/``\\n``)
    are tolerated; any other surrounding or embedded whitespace, junk
    characters or wrong-length payloads raise
    ``private_unavailable:invalid_key``. Decoding uses strict
    validation, so appended junk (``base64(key) + '!!!'``) is rejected
    instead of silently ignored. Empty/missing input raises
    ``private_unavailable:no_key``. The input is never echoed.
    """
    if value is None:
        raise PrivateUnavailable(UNAVAILABLE_NO_KEY)
    raw = _secret_value(value)
    if isinstance(raw, bytes):
        if len(raw) == KEY_BYTES:
            return bytes(raw)
        raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    if not isinstance(raw, str):
        raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    text = raw.strip("\r\n")
    if not text:
        raise PrivateUnavailable(UNAVAILABLE_NO_KEY)
    if _HEX_RE.match(text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY) from None
    if len(text) > 45 or len(text) < 43:
        # Base64 of 32 bytes is 44 chars padded, 43 unpadded; anything
        # else cannot decode to 32 bytes. This bound also keeps the
        # strict decoders below on a short leash.
        raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    if len(text) % 4 == 1:
        raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    padded = text + "=" * (-len(text) % 4)
    if _B64STD_RE.match(padded):
        try:
            decoded = base64.b64decode(padded.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            pass
        else:
            if len(decoded) == KEY_BYTES:
                return decoded
            raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    if _B64URL_RE.match(padded):
        try:
            decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            pass
        else:
            if len(decoded) == KEY_BYTES:
                return decoded
            raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY) from None


def load_ip_key(explicit: object = None) -> bytes | None:
    """Return the configured original-IP key, or ``None`` when absent.

    ``explicit`` (an already-resolved setting/CLI value) wins over the
    ``ORIGINAL_IP_KEY`` environment variable. Returns ``None`` only when
    no key is configured; a configured-but-malformed key raises
    ``private_unavailable:invalid_key`` instead of silently disabling.
    """
    if explicit is not None:
        unwrapped = _secret_value(explicit)
        blank_str = isinstance(unwrapped, str) and not unwrapped.strip()
        blank_bytes = isinstance(unwrapped, bytes) and not unwrapped
        if blank_str or blank_bytes:
            explicit = None
    source = explicit if explicit is not None else os.environ.get(IP_KEY_ENV)
    if source is None:
        return None
    return parse_ip_key(source)


def require_ip_key(explicit: object = None) -> bytes:
    """Return the configured key or raise a fixed unavailable code."""
    key = load_ip_key(explicit)
    if key is None:
        raise PrivateUnavailable(UNAVAILABLE_NO_KEY)
    for name in _FORBIDDEN_KEY_NAMES:
        other = os.environ.get(name)
        if other and _constant_equal_secret(other, key):
            raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    return key


def _constant_equal_secret(other: str, key: bytes) -> bool:
    """Whether ``other`` decodes to the same key bytes under any accepted form.

    Equivalent encodings (standard/URL-safe base64, padded or unpadded,
    hex, raw) are normalized through :func:`parse_ip_key` first, so an
    unpadded URL-safe spelling cannot bypass key separation.
    """
    import hmac as _hmac

    try:
        return _hmac.compare_digest(parse_ip_key(other), key)
    except PrivateUnavailable:
        pass
    try:
        if isinstance(other, str) and _hmac.compare_digest(other.encode("utf-8"), key):
            return True
    except (ValueError, TypeError):
        pass
    return False


def validate_original_ip(text: str) -> str | None:
    """Return ``text`` when it is a valid IPv4/IPv6 address, else ``None``.

    Ingestion-local validation (see :mod:`app.ingestion.combined`); kept
    here for compatibility. The textual form is preserved exactly
    (including IPv6 spellings) so the legacy HMAC input stays byte-exact.
    """
    from app.ingestion.combined import validate_original_ip as _validate

    return _validate(text)


def build_aad(*, site_id: str, source_id: str, file_fingerprint: str, byte_offset: int) -> bytes:
    """Associated data binding ciphertext to one site/source/event identity.

    The tuple is length-prefixed (each field as 4-byte big-endian length
    plus bytes) under a version prefix, so the encoding is unambiguous
    even when identifiers carry embedded delimiters -- unlike a
    zero-delimited join, ``("a\\x00b", "c")`` can never collide with
    ``("a", "b\\x00c")``. Swapped ciphertext (another event, source or
    site) carries different AAD and fails closed at decrypt time.
    """
    parts = [
        AAD_VERSION,
        site_id.encode("utf-8"),
        source_id.encode("utf-8"),
        file_fingerprint.encode("utf-8"),
        str(byte_offset).encode("utf-8"),
    ]
    framed = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return b"logcarve-aad-v2:" + len(framed).to_bytes(4, "big") + framed


def encrypt_ip(ip_text: str, *, key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt one validated address; return ``(nonce, ciphertext)``.

    A fresh random 12-byte nonce is generated for every call and never
    reused. ``ip_text`` must pass :func:`validate_original_ip`.
    """
    if validate_original_ip(ip_text) is None:
        raise ValueError("ip_text must be a valid IPv4/IPv6 address")
    if len(key) != KEY_BYTES:
        raise PrivateUnavailable(UNAVAILABLE_INVALID_KEY)
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, ip_text.encode("utf-8"), aad)
    return nonce, ciphertext


def _coerce_blob(value: object, *, what: str) -> bytes:
    """Coerce a stored SQLite blob to bytes; fail closed on wrong types.

    A malformed ``request_original_ips`` row (TEXT nonce/ciphertext,
    NULL, truncated values) maps to the fixed
    ``private_unavailable:decrypt_failed`` code -- never an uncaught
    ``TypeError``, and never the stored value.
    """
    _ = what
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED)


def encrypt_captured(captured: object, *, key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt one transient capture; reveal happens only here.

    ``captured`` must be a :class:`app.ingestion.combined.CapturedOriginal`;
    anything else (a bare string, ``None``) is refused. Import and
    reprocess paths pass the capture straight here, so ``reveal()`` is
    never called outside this proven private function.
    """
    from app.ingestion.combined import CapturedOriginal

    if not isinstance(captured, CapturedOriginal):
        raise TypeError("captured must be a CapturedOriginal")
    return encrypt_ip(captured.reveal(), key=key, aad=aad)


def decrypt_ip(nonce: bytes, ciphertext: bytes, *, key: bytes, aad: bytes) -> str:
    """Decrypt one stored address; fail closed with a fixed code.

    Wrong keys, swapped AAD (event/site) or tampered bytes raise
    ``private_unavailable:decrypt_failed`` (``InvalidTag`` underneath).
    Malformed blob types fail the same fixed way. No
    plaintext/ciphertext fallback is ever returned.
    """
    try:
        nonce = _coerce_blob(nonce, what="nonce")
        ciphertext = _coerce_blob(ciphertext, what="ciphertext")
        key = _coerce_blob(key, what="key")
        aad = _coerce_blob(aad, what="aad")
    except PrivateUnavailable:
        raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED) from None
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES or not ciphertext:
        raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED) from None
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED) from None
    if validate_original_ip(text) is None:
        raise PrivateUnavailable(UNAVAILABLE_DECRYPT_FAILED) from None
    return text


def store_private_ip(
    conn: sqlite3.Connection,
    *,
    request_id: int,
    nonce: bytes,
    ciphertext: bytes,
    created_at: str | None = None,
) -> bool:
    """Store ciphertext for one request; never replace an existing original.

    ``INSERT OR IGNORE`` keeps the first stored original: reprocessing or
    a replaying import cannot replace an original with a different
    HMAC client's address. Returns ``True`` when a row was inserted.
    """
    if created_at is None:
        created_at = datetime.now(UTC).isoformat()
    cursor = conn.execute(
        "INSERT OR IGNORE INTO request_original_ips"
        " (request_id, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?)",
        (request_id, bytes(nonce), bytes(ciphertext), created_at),
    )
    return cursor.rowcount == 1


def fetch_private_row(conn: sqlite3.Connection, *, request_id: int) -> tuple[bytes, bytes] | None:
    """Return ``(nonce, ciphertext)`` for one request, or ``None``.

    Malformed stored blobs (wrong SQLite types) raise the fixed
    ``private_unavailable:decrypt_failed`` code instead of an uncaught
    ``TypeError``; the stored value is never echoed.
    """
    row = conn.execute(
        "SELECT nonce, ciphertext FROM request_original_ips WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    return (
        _coerce_blob(row[0], what="nonce"),
        _coerce_blob(row[1], what="ciphertext"),
    )


def count_private_rows(conn: sqlite3.Connection) -> int:
    """Number of stored encrypted originals (ciphertext only, never plaintext)."""
    return int(conn.execute("SELECT COUNT(*) FROM request_original_ips").fetchone()[0])


def read_original_ip(conn: sqlite3.Connection, *, request_id: int, key: bytes) -> str:
    """Read one original address through the explicit private channel.

    The AAD is derived from the parent ``requests`` row the ciphertext is
    attached to, so ciphertext copied onto another event, source or site
    fails closed. Missing rows or missing ciphertext raise fixed
    unavailable codes.
    """
    row = conn.execute(
        "SELECT site_id, source_id, file_fingerprint, byte_offset FROM requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise PrivateUnavailable(UNAVAILABLE_NOT_STORED)
    site_id, source_id, file_fingerprint, byte_offset = row
    stored = fetch_private_row(conn, request_id=request_id)
    if stored is None:
        raise PrivateUnavailable(UNAVAILABLE_NOT_STORED)
    nonce, ciphertext = stored
    aad = build_aad(
        site_id=site_id,
        source_id=source_id,
        file_fingerprint=file_fingerprint,
        byte_offset=int(byte_offset),
    )
    return decrypt_ip(nonce, ciphertext, key=key, aad=aad)


def get_ip_display_mode(conn: sqlite3.Connection) -> str:
    """Persisted local-admin original-IP display mode; default ``full``."""
    row = conn.execute(
        "SELECT value FROM admin_settings WHERE key = ?", (_IP_DISPLAY_SETTING_KEY,)
    ).fetchone()
    if row is None:
        return IP_DISPLAY_FULL
    mode = str(row[0])
    if mode not in IP_DISPLAY_MODES:
        return IP_DISPLAY_FULL
    return mode


def set_ip_display_mode(conn: sqlite3.Connection, mode: str) -> str:
    """Persist the local-admin display mode; reject unknown modes."""
    if mode not in IP_DISPLAY_MODES:
        raise ValueError(f"unknown ip display mode: {mode!r}")
    conn.execute(
        "INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value,"
        " updated_at = excluded.updated_at",
        (_IP_DISPLAY_SETTING_KEY, mode, datetime.now(UTC).isoformat()),
    )
    return mode


def mask_ip_suffix(ip_text: str) -> str:
    """Display masking for ``suffix_mask`` mode: hide the address suffix.

    IPv4 hides the last octet (``192.0.2.*``); IPv6 hides the last 64
    bits, keeping the /64 prefix (``2001:db8:1:2::*``). This is display
    masking only, never proof of anonymity.
    """
    parsed = ipaddress.ip_address(ip_text)
    if isinstance(parsed, ipaddress.IPv4Address):
        parts = ip_text.split(".")
        if len(parts) != 4:
            raise ValueError("invalid IPv4 display form")
        return ".".join(parts[:3]) + ".*"
    groups = parsed.exploded.split(":")
    return ":".join(groups[:4]) + ":*"


def format_original_for_display(ip_text: str, pseudonym: str, mode: str) -> str:
    """Render a decrypted original under the persisted display mode.

    ``full`` returns the address, ``suffix_mask`` hides the suffix octets
    or hextets, ``pseudonym_only`` returns the stable HMAC pseudonym.
    """
    if mode not in IP_DISPLAY_MODES:
        raise ValueError(f"unknown ip display mode: {mode!r}")
    if mode == IP_DISPLAY_PSEUDONYM_ONLY:
        return pseudonym
    if validate_original_ip(ip_text) is None:
        raise ValueError("ip_text must be a valid IPv4/IPv6 address")
    if mode == IP_DISPLAY_SUFFIX_MASK:
        return mask_ip_suffix(ip_text)
    return ip_text

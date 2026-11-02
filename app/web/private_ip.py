"""Session-gated original-IP display for the local-admin dashboard (T4a).

Reads run INSIDE the caller's read snapshot (same connection that
served the sanitized explorer page, so a concurrent follow/refresh
batch cannot pair one event with another event's original). Each
displayed row binds by its internal ``requests.id`` primary key —
never by timestamp/path/pseudonym or row ordinal — so legitimate
identical adjacent rows each resolve to their own event.

Server-side discipline:

- Decrypt-then-mask happens here, before any template touches the
  value. Masked modes never place the hidden suffix in the DOM,
  attributes, titles, JSON or details: the plaintext suffix is
  dropped at this layer.
- Missing/invalid/wrong keys, tampered ciphertext and unenriched
  legacy rows all surface as fixed ``unavailable`` states with an
  honest recovery hint (reprocess the read-only source; a lost key
  cannot be repaired by pretending the HMAC pseudonym recovers the
  original). No ciphertext, key material or original ever leaves this
  module except the already-masked display string.
- Bearer [REDACTED] shared DTOs, the external API, exports and model
  tools never call this module.
"""

import sqlite3

from app.db import private


def key_status(conn: sqlite3.Connection) -> tuple[bytes | None, str | None]:
    """Configured original-IP key, or ``(None, fixed_code)`` when absent.

    Returns the key bytes on success; otherwise the fixed
    ``private_unavailable:*`` code (``no_key`` / ``invalid_key``).
    The input is never echoed.
    """
    try:
        return private.require_ip_key(), None
    except private.PrivateUnavailable as exc:
        return None, exc.code


def attach_private(
    conn: sqlite3.Connection,
    paired: list[tuple[int, dict[str, object]]],
    *,
    key: bytes | None,
    key_code: str | None,
    state: dict[str, object],
) -> list[dict[str, object]]:
    """Bind each ``(request_id, row)`` pair to its display original.

    ``state`` is :func:`app.db.private.resolve_display_state`. Every
    row gains ``ip_display`` (the only address-derived string the
    templates may render), ``ip_state`` (``shown`` / ``masked`` /
    ``pseudonym`` / ``unavailable``) and ``ip_notice`` (a central
    locale key for the unavailable/pseudonym guidance, or ``None``).
    ``client_pseudonym`` values, counts, order and paging are
    untouched: display changes never alter shared analytics identity.
    """
    mode = str(state.get("mode", private.IP_DISPLAY_PSEUDONYM_ONLY))
    v4_hidden = int(state.get("v4_hidden", private.DEFAULT_HIDDEN_V4))  # type: ignore[arg-type]
    v6_hidden = int(state.get("v6_hidden", private.DEFAULT_HIDDEN_V6))  # type: ignore[arg-type]
    rows: list[dict[str, object]] = []
    for request_id, row in paired:
        pseudonym = str(row.get("client_pseudonym", ""))
        display, ip_state, notice = _display_for(
            conn,
            request_id=request_id,
            pseudonym=pseudonym,
            mode=mode,
            v4_hidden=v4_hidden,
            v6_hidden=v6_hidden,
            key=key,
            key_code=key_code,
        )
        rows.append({**row, "ip_display": display, "ip_state": ip_state, "ip_notice": notice})
    return rows


def _display_for(
    conn: sqlite3.Connection,
    *,
    request_id: int,
    pseudonym: str,
    mode: str,
    v4_hidden: int,
    v6_hidden: int,
    key: bytes | None,
    key_code: str | None,
) -> tuple[str, str, str | None]:
    """One row's ``(display, state, notice_key)`` triple, fail-closed."""
    if mode == private.IP_DISPLAY_PSEUDONYM_ONLY:
        return pseudonym, "pseudonym", "privacy.ip_pseudonym_only"
    if key is None:
        return pseudonym, "unavailable", _notice_for(key_code)
    try:
        original = private.read_original_ip(conn, request_id=request_id, key=key)
    except private.PrivateUnavailable as exc:
        return pseudonym, "unavailable", _notice_for(exc.code)
    try:
        rendered = private.format_original_for_display(
            original, pseudonym, mode, v4_hidden=v4_hidden, v6_hidden=v6_hidden
        )
    except ValueError:
        return pseudonym, "unavailable", "privacy.ip_unavailable_scoped"
    if mode == private.IP_DISPLAY_SUFFIX_MASK:
        _assert_suffix_absent(original, rendered)
        return rendered, "masked", None
    return rendered, "shown", None


def banner_key(code: str | None) -> str:
    """Central English guidance key for the page-level IP banner.

    The raw ``private_unavailable:*`` store codes are never locale keys;
    rendering them would leak internal codes as raw labels. Every code
    maps to one fixed ``privacy.ip_*`` guidance string instead.
    """
    return _notice_for(code)


def _notice_for(code: str | None) -> str:
    """Fixed recovery guidance per unavailable cause; never echoes input."""
    if code == private.UNAVAILABLE_NO_KEY:
        return "privacy.ip_unavailable_no_key"
    if code == private.UNAVAILABLE_INVALID_KEY:
        return "privacy.ip_unavailable_invalid_key"
    if code == private.UNAVAILABLE_DECRYPT_FAILED:
        return "privacy.ip_unavailable_decrypt_failed"
    return "privacy.ip_unavailable_not_stored"


def _assert_suffix_absent(original: str, rendered: str) -> None:
    """Guard: the masked display must not still carry the hidden suffix.

    A masked value that still contains the original full text (or, for
    IPv4, its last visible octet group) is a masking bug: fail closed
    to unavailable instead of rendering it. This is a last-resort
    invariant — masking itself happens in :mod:`app.db.private`.
    """
    if original and (original == rendered or original in rendered):
        raise ValueError("masked display still carries the original")


def safe_referrer_url(scheme: object, host: object, path: object) -> str | None:
    """Sanitized absolute referrer link, or ``None`` when not linkable.

    Only ``http``/``https`` links are ever produced, with control
    characters, backslashes and non-ASCII hosts rejected; anything
    else (missing parts, dangerous schemes such as ``javascript:`` or
    ``data:``, secret-bearing oddities) yields ``None`` so templates
    render plain text instead of a link. Query values are never stored
    and therefore never appear here.
    """
    if not isinstance(scheme, str) or not isinstance(host, str):
        return None
    protocol = scheme.strip().lower()
    if protocol not in ("http", "https"):
        return None
    hostname = host.strip()
    if (
        not hostname
        or len(hostname) > 253
        or "\\" in hostname
        or " " in hostname
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in hostname)
        or not hostname.isascii()
    ):
        return None
    suffix = ""
    if isinstance(path, str) and path:
        if (
            not path.startswith("/")
            or "\\" in path
            or " " in path
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in path)
        ):
            return None
        suffix = path
    return f"{protocol}://{hostname}{suffix}"

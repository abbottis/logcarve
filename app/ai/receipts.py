"""Stateless evidence receipts for local revalidation (no migration).

Every assistant tool envelope carries compact provenance (per-source
generation and import heads, scope event counts, observed range — read
by ``app.analytics.provenance``) plus a SHA-256 digest of the canonical
result. A receipt binds the exact replay scope (tool plus filters) to
those digests with HMAC-SHA256 keyed by the server ``session_secret``.
Receipts are opaque strings for the authenticated browser only: they
carry no raw rows, paths, lines, original addresses, keys or
fingerprint internals, they never enter the provider wire, and they
create no tables. Legacy evidence without a receipt is unverifiable,
never silently current.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from app.analytics.provenance import RECEIPT_VERSION

#: Verification rejects anything larger outright, before any decode or
#: comparison work. Legitimate receipts are a few kilobytes (bounded
#: replay filters plus compact heads); the HTTP body bound stays the
#: outer limit.
RECEIPT_MAX_LENGTH = 65536
#: Decoded payload ceiling: the canonical JSON of bounded filters plus
#: compact provenance heads.
RECEIPT_MAX_DECODED_BYTES = 65536

#: Receipt payload keys; anything else in a presented receipt fails closed.
_RECEIPT_FIELDS = frozenset(
    {"v", "tool", "filters", "result_digest", "provenance", "observation_time"}
)


def canonical_json_bytes(value: object) -> bytes:
    """Canonical bytes for digests: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


#: Volatile observation timestamps stripped from the comparison digest.
#: Named explicitly and narrowly: ``generated_at`` (summary/performance
#: envelopes) and ``observation_time`` (finding items). Every data field
#: — counts, agents, windows, filters, coverage heads — stays covered, so
#: a same-count/different-evidence change still mismatches. Stripped
#: timestamps are never lost: original and fresh observation times travel
#: beside the receipt and inside the fresh result.
VOLATILE_DIGEST_KEYS = frozenset({"generated_at", "observation_time"})


def _strip_volatile(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_volatile(item)
            for key, item in value.items()
            if key not in VOLATILE_DIGEST_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [_strip_volatile(item) for item in value]
    return value


def result_digest(result: object) -> str:
    """SHA-256 hex over the canonical result minus volatile timestamps.

    Observation time, coverage and provenance are compared separately, so
    an observation-time-only replay still matches while a
    same-count/different-evidence change does not.
    """
    return hashlib.sha256(canonical_json_bytes(_strip_volatile(result))).hexdigest()


def _b64encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), altchars=b"-_", validate=True)


def sign_receipt(payload: dict[str, object], *, secret: str) -> str:
    """Bind one replay scope to its digests; returns the opaque receipt."""
    body = _b64encode(canonical_json_bytes(payload))
    sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_receipt(receipt: str, *, secret: str) -> dict[str, object] | None:
    """Return the receipt payload when the signature and shape are valid.

    Any malformed, foreign-versioned, extra-field or mis-signed receipt
    returns None: callers fail closed without executing anything. The
    function never raises for hostile input — non-ASCII signatures,
    invalid base64, odd field types and oversize values all fail closed
    (``hmac.compare_digest`` raises ``TypeError`` on non-ASCII text, so
    every encode/compare/decode step is guarded).
    """
    if not isinstance(receipt, str) or not isinstance(secret, str):
        return None
    if not secret or not receipt or "." not in receipt:
        return None
    if len(receipt) > RECEIPT_MAX_LENGTH:
        return None
    body, _, sig = receipt.rpartition(".")
    if not body or not sig or len(body) > RECEIPT_MAX_LENGTH:
        return None
    try:
        expected = hmac.new(
            secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        # Compare as ASCII bytes: a non-ASCII ``sig`` raises here
        # instead of reaching the digest comparison.
        valid = hmac.compare_digest(sig.encode("ascii"), expected.encode("ascii"))
    except (TypeError, ValueError):
        return None
    if not valid:
        return None
    try:
        raw = _b64decode(body)
        if len(raw) > RECEIPT_MAX_DECODED_BYTES:
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if set(payload.keys()) != _RECEIPT_FIELDS:
        return None
    if payload.get("v") != RECEIPT_VERSION:
        return None
    tool = payload.get("tool")
    if not isinstance(tool, str) or not tool:
        return None
    if not isinstance(payload.get("filters"), dict):
        return None
    digest = payload.get("result_digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        return None
    if not isinstance(payload.get("provenance"), dict):
        return None
    if not isinstance(payload.get("observation_time"), str):
        return None
    return payload


def receipt_payload(
    *,
    tool: str,
    filters: dict[str, object],
    digest: str,
    provenance: dict[str, object],
    observation_time: str,
) -> dict[str, object]:
    """Exact replay scope plus digests; the ONLY trusted recheck input."""
    return {
        "v": RECEIPT_VERSION,
        "tool": tool,
        "filters": filters,
        "result_digest": digest,
        "provenance": provenance,
        "observation_time": observation_time,
    }

"""Stateless evidence receipts for local revalidation (no migration).

Every assistant tool envelope carries compact provenance (per-source
generation and import heads, scope event counts, observed range) plus a
SHA-256 digest of the canonical result. A receipt binds the exact replay
scope (tool plus filters) to those digests with HMAC-SHA256 keyed by the
server ``session_secret``. Receipts are opaque strings for the
authenticated browser only: they carry no raw rows, paths, lines,
original addresses, keys or fingerprint internals, they never enter the
provider wire, and they create no tables. Legacy evidence without a
receipt is unverifiable, never silently current.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3

RECEIPT_VERSION = "ev-receipt-1"

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


def build_provenance(
    conn: sqlite3.Connection,
    *,
    site_id: str,
    source_id: str | None,
    unique_events: object,
    observed_min: object,
    observed_max: object,
    imports_truncated: bool,
    digest: str,
) -> dict[str, object]:
    """Compact generation heads for the exact envelope scope.

    Per scoped source: the latest follow/rotation generation (seq and
    opaque generation id, both None when the source never followed) and
    the latest import head id. No fingerprints, paths, counts of raw
    bytes or secrets: heads are opaque references, and a wider report
    scope is disclosed through the scope fields below rather than
    implying the old result was lost. Partial/capped history is stated
    via ``imports_truncated`` instead of a stronger claim.
    """
    try:
        if source_id is not None:
            scoped_sources = [source_id]
        else:
            scoped_sources = [
                row[0]
                for row in conn.execute(
                    "SELECT id FROM log_sources WHERE site_id = ? ORDER BY id",
                    [site_id],
                ).fetchall()
            ]
    except (sqlite3.Error, OSError):
        scoped_sources = [source_id] if source_id is not None else []
    sources: list[dict[str, object]] = []
    for scoped in scoped_sources:
        generation_seq: object = None
        generation_id: object = None
        import_head_id: object = None
        try:
            row = conn.execute(
                "SELECT generation_seq, generation_id FROM follow_generations"
                " WHERE source_id = ? ORDER BY generation_seq DESC LIMIT 1",
                [scoped],
            ).fetchone()
            if row is not None:
                generation_seq, generation_id = row[0], row[1]
            head = conn.execute(
                "SELECT MAX(id) FROM imports WHERE source_id = ?", [scoped]
            ).fetchone()
            if head is not None:
                import_head_id = head[0]
        except (sqlite3.Error, OSError):
            pass
        sources.append(
            {
                "source_id": scoped,
                "generation_seq": generation_seq,
                "generation_id": generation_id,
                "import_head_id": import_head_id,
            }
        )
    return {
        "version": RECEIPT_VERSION,
        "site_id": site_id,
        "source_id": source_id,
        "sources": sources,
        "unique_events": unique_events,
        "observed_min": observed_min,
        "observed_max": observed_max,
        "imports_truncated": bool(imports_truncated),
        "result_digest": digest,
    }


def _b64encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def sign_receipt(payload: dict[str, object], *, secret: str) -> str:
    """Bind one replay scope to its digests; returns the opaque receipt."""
    body = _b64encode(canonical_json_bytes(payload))
    sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_receipt(receipt: str, *, secret: str) -> dict[str, object] | None:
    """Return the receipt payload when the signature and shape are valid.

    Any malformed, foreign-versioned, extra-field or mis-signed receipt
    returns None: callers fail closed without executing anything.
    """
    if not isinstance(receipt, str) or "." not in receipt:
        return None
    body, _, sig = receipt.rpartition(".")
    if not body or not sig:
        return None
    try:
        expected = hmac.new(
            secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
    except (TypeError, ValueError):
        return None
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if set(payload.keys()) != _RECEIPT_FIELDS:
        return None
    if payload.get("v") != RECEIPT_VERSION:
        return None
    if not isinstance(payload.get("tool"), str) or not isinstance(payload.get("filters"), dict):
        return None
    if not isinstance(payload.get("result_digest"), str) or not isinstance(
        payload.get("provenance"), dict
    ):
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

"""Bounded source/generation provenance reads (shared analytics ownership).

The per-evidence provenance heads (latest follow/rotation generation
plus latest import head per scoped source) are storage reads, so they
live with the deterministic analytics layer — not with the signing
serializer under ``app/ai``. Queries are typed, parameterized and
bounded: the configured-source listing carries an explicit LIMIT and
reports truncation instead of implying completeness.

A missing table or unreadable store raises ``sqlite3.Error``/``OSError``
to the caller (mapped to ``ToolError("store_unavailable")`` by the tool
layer). A known source that was never followed is NOT an error: its
generation fields stay ``None`` with ``complete`` true. Only a hit
provenance cap (or a store failure) withholds the completeness claim.
"""

from __future__ import annotations

import sqlite3

#: Provenance envelope version, checked by the receipt verifier.
RECEIPT_VERSION = "ev-receipt-1"

#: Hard cap on the configured-source listing inside one provenance
#: envelope. Past the cap the envelope reports ``complete: False``
#: and revalidation refuses any ``current`` claim.
MAX_PROVENANCE_SOURCES = 64


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
    via ``imports_truncated`` instead of a stronger claim, and a
    truncated source listing is stated via ``complete: False``.

    Storage failures propagate: a missing ``follow_generations``,
    ``imports`` or ``log_sources`` table (or any other read error)
    raises instead of collapsing into ``None`` heads that would read
    as "known source, never followed".
    """
    complete = True
    if source_id is not None:
        scoped_sources = [source_id]
    else:
        rows = conn.execute(
            "SELECT id FROM log_sources WHERE site_id = ? ORDER BY id LIMIT ?",
            [site_id, MAX_PROVENANCE_SOURCES + 1],
        ).fetchall()
        complete = len(rows) <= MAX_PROVENANCE_SOURCES
        scoped_sources = [row[0] for row in rows[:MAX_PROVENANCE_SOURCES]]
    sources: list[dict[str, object]] = []
    for scoped in scoped_sources:
        row = conn.execute(
            "SELECT generation_seq, generation_id FROM follow_generations"
            " WHERE source_id = ? ORDER BY generation_seq DESC LIMIT 1",
            [scoped],
        ).fetchone()
        generation_seq: object = row[0] if row is not None else None
        generation_id: object = row[1] if row is not None else None
        head = conn.execute("SELECT MAX(id) FROM imports WHERE source_id = ?", [scoped]).fetchone()
        import_head_id: object = head[0] if head is not None else None
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
        "complete": complete,
        "result_digest": digest,
    }

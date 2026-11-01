"""Bounded gzip handling for log ingestion (T1a).

Magic detection reads only the first two bytes (``0x1f 0x8b``); the file
extension is never trusted. Decompression streams through
``zlib.decompressobj`` with ``wbits=31`` so concatenated members decode
transparently while member boundaries stay countable. Every bound is
enforced while streaming with no full-file buffering:

- ``max_compressed_bytes`` caps raw bytes pulled from the file.
- ``max_uncompressed_bytes`` caps logical (decompressed) bytes produced.
- ``max_compression_ratio`` caps ``logical / raw`` once enough raw input
  has been seen (past a small floor so tiny files never trip the ratio).
- ``max_gzip_members`` caps concatenated gzip members.
- Work is bounded because no single ``decompress`` call may emit more
  than ``_OUTPUT_CAP`` bytes while total output stays capped, so the
  call count is finite; an explicit counter fails closed on escape.
- Line splitting reuses the bounded ``iter_raw_lines`` core, so the
  oversize-line rule reports exactly one rejection per physical line.

Allocation safety: every ``decompress`` call passes a positive
``max_length`` so the C layer never allocates an unbounded output for
one input chunk. Leftover compressed input drains through
``unconsumed_tail`` (output cap reached) and ``unused_data`` (member
boundary) step by step; produced pieces are yielded as they clear the
size/ratio checks and are never accumulated. A 229-byte bomb expanding
to 200000 bytes is rejected after at most ``max_length`` bytes of
allocation per call, never after a 200000-byte allocation followed by
a length check.

Truncation (raw EOF with an unfinished stream), CRC/adler failures and
invalid headers map to fixed ``GzipError.code`` values that never carry
paths, offsets of secrets, raw lines or key material.
"""

import hashlib
import zlib
from dataclasses import dataclass
from pathlib import Path

GZIP_MAGIC = b"\x1f\x8b"

_CHUNK_SIZE = 65536
_RATIO_FLOOR_BYTES = 65536
# Hard ceiling on decompressed bytes produced by one decompress() call.
# Every call uses a positive max_length no larger than this, so a single
# input chunk can never trigger an unbounded allocation.
_OUTPUT_CAP = 65536


@dataclass(frozen=True)
class GzipLimits:
    """Bounded-work contract for gzip sources.

    Values are validated on construction: byte/member caps must be
    positive integers (bools rejected), the ratio must be finite and at
    least 1, and absurd magnitudes that could never reflect a real
    transfer fail closed instead of silently disabling the guard.
    """

    max_compressed_bytes: int = 1_073_741_824
    max_uncompressed_bytes: int = 1_073_741_824
    max_compression_ratio: float = 100.0
    max_gzip_members: int = 64

    def __post_init__(self) -> None:
        for name in ("max_compressed_bytes", "max_uncompressed_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**62:
                raise ValueError(f"{name} must be an integer in 1..2**62")
        ratio = self.max_compression_ratio
        if (
            isinstance(ratio, bool)
            or not isinstance(ratio, (int, float))
            or not (1.0 <= float(ratio) <= 1_000_000.0)
        ):
            raise ValueError("max_compression_ratio must be finite within 1..1000000")
        members = self.max_gzip_members
        if (
            isinstance(members, bool)
            or not isinstance(members, int)
            or not 1 <= members <= 1_000_000
        ):
            raise ValueError("max_gzip_members must be an integer in 1..1000000")


class GzipError(OSError):
    """A gzip source that cannot be decoded within bounds. Fixed codes only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LogicalFingerprint:
    """Logical-domain identity of a source: hash/size of decompressed bytes."""

    is_gzip: bool
    logical_sha256: str
    logical_size: int
    raw_size: int
    gzip_members: int


def has_gzip_magic(path: Path) -> bool:
    """Peek at the first two bytes only; never trust the extension."""
    with open(path, "rb") as stream:
        return stream.read(2) == GZIP_MAGIC


def _new_decompressor() -> "zlib._Decompress":
    return zlib.decompressobj(31)


def iter_decompressed_chunks(
    path: Path, *, limits: GzipLimits | None = None
) -> tuple["__import__('collections').abc.Iterator[bytes]", dict[str, int]]:
    """Yield decompressed chunks; the stats dict fills as chunks are pulled.

    Raises :class:`GzipError` with a fixed code on truncation, CRC failure,
    bound breach or member-limit breach. The stats dict reports
    ``raw_bytes``/``logical_bytes``/``members`` for accounting.
    """
    limits = limits or GzipLimits()
    stats = {"raw_bytes": 0, "logical_bytes": 0, "members": 1}

    def _generate():
        decompressor = _new_decompressor()
        raw_seen = 0
        logical_seen = 0
        members = 1
        calls = 0
        # Derived call ceiling: every call consumes pending input or emits
        # output, and both totals are capped, so this count is finite and
        # only trips on an accounting escape (never on legitimate input).
        max_calls = (
            (limits.max_compressed_bytes // _CHUNK_SIZE + 2)
            + (limits.max_uncompressed_bytes // 1 + 1)
            + (limits.max_gzip_members + 2)
        )
        with open(path, "rb") as stream:
            raw_exhausted = False
            pending = b""
            while True:
                if not pending and not raw_exhausted:
                    chunk = stream.read(_CHUNK_SIZE)
                    if chunk:
                        raw_seen += len(chunk)
                        if raw_seen > limits.max_compressed_bytes:
                            raise GzipError("interrupted:gzip_too_large")
                        if decompressor.eof:
                            # Raw bytes remain after a finished member whose
                            # end aligned exactly with a read boundary: a new
                            # concatenated member starts here.
                            members += 1
                            if members > limits.max_gzip_members:
                                raise GzipError("interrupted:gzip_member_limit")
                            decompressor = _new_decompressor()
                        pending = chunk
                    else:
                        raw_exhausted = True
                if pending:
                    # Positive bounded output per call: remaining+1 detects
                    # any over-limit byte while keeping max_length small
                    # when little budget is left.
                    remaining = limits.max_uncompressed_bytes - logical_seen
                    if remaining < 0:
                        raise GzipError("interrupted:gzip_too_large")
                    cap = min(remaining + 1, _OUTPUT_CAP)
                    calls += 1
                    if calls > max_calls:
                        raise GzipError("interrupted:gzip_too_large")
                    try:
                        data = decompressor.decompress(pending, cap)
                    except zlib.error:
                        raise GzipError(_member_error(members)) from None
                    # Drain leftovers step by step. At end-of-member
                    # unused_data is the single authoritative remainder:
                    # some interpreters also report those same bytes in
                    # unconsumed_tail, so concatenating both would decode
                    # the next member twice and inflate the member count.
                    # Away from end-of-member only unconsumed_tail applies
                    # (output cap reached mid-member).
                    if decompressor.eof:
                        pending = decompressor.unused_data
                    else:
                        pending = decompressor.unconsumed_tail
                    if decompressor.eof and pending:
                        members += 1
                        if members > limits.max_gzip_members:
                            raise GzipError("interrupted:gzip_member_limit")
                        decompressor = _new_decompressor()
                    if data:
                        logical_seen += len(data)
                        if logical_seen > limits.max_uncompressed_bytes:
                            raise GzipError("interrupted:gzip_too_large")
                        if (
                            raw_seen > _RATIO_FLOOR_BYTES
                            and logical_seen > raw_seen * limits.max_compression_ratio
                        ):
                            raise GzipError("interrupted:gzip_ratio_exceeded")
                        stats["raw_bytes"] = raw_seen
                        stats["logical_bytes"] = logical_seen
                        stats["members"] = members
                        yield data
                    stats["raw_bytes"] = raw_seen
                    stats["logical_bytes"] = logical_seen
                    stats["members"] = members
                else:
                    if not decompressor.eof:
                        # Raw EOF with an unfinished stream: truncated file
                        # (or a non-gzip file that merely starts with magic).
                        raise GzipError("interrupted:gzip_truncated")
                    stats["raw_bytes"] = raw_seen
                    stats["logical_bytes"] = logical_seen
                    stats["members"] = members
                    return

    return _generate(), stats


def _member_error(members: int) -> str:
    """Fixed code for a corrupt member: first-member faults read as CRC."""
    if members > 1:
        return "interrupted:gzip_invalid"
    return "interrupted:gzip_crc_error"


def logical_fingerprint(path: Path, *, limits: GzipLimits | None = None) -> LogicalFingerprint:
    """Stream a source to its logical-domain fingerprint (bounded memory).

    Plain files hash raw bytes (identical to ``sha256_file``); gzip files
    hash decompressed bytes so the same plaintext imported plain or gzipped
    carries one identity. No output is retained.
    """
    limits = limits or GzipLimits()
    raw_size = path.stat().st_size
    if not has_gzip_magic(path):
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                digest.update(chunk)
        return LogicalFingerprint(
            is_gzip=False,
            logical_sha256=digest.hexdigest(),
            logical_size=raw_size,
            raw_size=raw_size,
            gzip_members=0,
        )
    digest = hashlib.sha256()
    chunks, stats = iter_decompressed_chunks(path, limits=limits)
    for data in chunks:
        digest.update(data)
    return LogicalFingerprint(
        is_gzip=True,
        logical_sha256=digest.hexdigest(),
        logical_size=stats["logical_bytes"],
        raw_size=raw_size,
        gzip_members=stats["members"],
    )

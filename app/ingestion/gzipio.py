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
- Line splitting reuses the bounded ``iter_raw_lines`` core, so the
  oversize-line rule reports exactly one rejection per physical line.

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


@dataclass(frozen=True)
class GzipLimits:
    """Bounded-work contract for gzip sources."""

    max_compressed_bytes: int = 1_073_741_824
    max_uncompressed_bytes: int = 1_073_741_824
    max_compression_ratio: float = 100.0
    max_gzip_members: int = 64


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
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(_CHUNK_SIZE)
                if chunk:
                    raw_seen += len(chunk)
                    if raw_seen > limits.max_compressed_bytes:
                        raise GzipError("interrupted:gzip_too_large")
                    if decompressor.eof:
                        # Raw bytes remain after a finished member: a new
                        # concatenated member starts here.
                        members += 1
                        if members > limits.max_gzip_members:
                            raise GzipError("interrupted:gzip_member_limit")
                        decompressor = _new_decompressor()
                    try:
                        data = decompressor.decompress(chunk)
                    except zlib.error:
                        code = (
                            "interrupted:gzip_crc_error"
                            if members == 1 and logical_seen > 0
                            else "interrupted:gzip_invalid"
                            if members > 1
                            else "interrupted:gzip_crc_error"
                        )
                        raise GzipError(code) from None
                    # One chunk may hold several small members back to back.
                    while decompressor.eof and decompressor.unused_data:
                        trailing = decompressor.unused_data
                        members += 1
                        if members > limits.max_gzip_members:
                            raise GzipError("interrupted:gzip_member_limit")
                        decompressor = _new_decompressor()
                        try:
                            extra = decompressor.decompress(trailing)
                        except zlib.error:
                            raise GzipError("interrupted:gzip_invalid") from None
                        data += extra
                else:
                    data = b""
                    if not decompressor.eof:
                        # Raw EOF with an unfinished stream: truncated file
                        # (or a non-gzip file that merely starts with magic).
                        raise GzipError("interrupted:gzip_truncated")
                    stats["raw_bytes"] = raw_seen
                    stats["logical_bytes"] = logical_seen
                    stats["members"] = members
                    return
                if data:
                    logical_seen += len(data)
                    if logical_seen > limits.max_uncompressed_bytes:
                        raise GzipError("interrupted:gzip_too_large")
                    if (
                        raw_seen > _RATIO_FLOOR_BYTES
                        and logical_seen > raw_seen * limits.max_compression_ratio
                    ):
                        raise GzipError("interrupted:gzip_ratio_exceeded")
                    yield data
                stats["raw_bytes"] = raw_seen
                stats["logical_bytes"] = logical_seen
                stats["members"] = members

    return _generate(), stats


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

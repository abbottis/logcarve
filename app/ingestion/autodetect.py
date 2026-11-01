"""Sampled format autodetection with bounded confidence (T1a).

Detection never guesses silently: each candidate preset scores the fraction
of sampled lines it parses, and the winner must clear both an absolute
confidence floor and a margin over the runner-up. Otherwise detection
reports ``ambiguous`` (or ``unmatched`` when nothing parses) and the caller
must require an explicit ``--format`` override. Richer grammars win ties:
Extended is tried before vhost before Combined before Common, and an
Apache escape observation prefers the Apache Combined variant.
"""

from dataclasses import dataclass
from pathlib import Path

from app.ingestion import combined as _combined
from app.ingestion.combined import Limits

MIN_CONFIDENCE = 0.8
MIN_MARGIN = 0.2
DEFAULT_SAMPLE_LINES = 32

_CANDIDATE_ORDER = (
    _combined.NGINX_EXTENDED,
    _combined.APACHE_VHOST_COMBINED,
    _combined.NGINX_COMBINED,
    _combined.APACHE_COMBINED,
    _combined.COMMON,
)


@dataclass(frozen=True)
class DetectResult:
    """Bounded autodetect outcome. ``format_id`` is set only when decided."""

    format_id: str | None
    confidence: float
    candidates: tuple[str, ...]
    ambiguous: bool
    samples: int


class AmbiguousFormat(ValueError):
    """Sampled detection could not decide; an explicit format is required."""

    def __init__(self, candidates: tuple[str, ...], confidence: float) -> None:
        super().__init__("interrupted:format_ambiguous")
        self.code = "interrupted:format_ambiguous"
        self.candidates = candidates
        self.confidence = confidence


class UnmatchedFormat(ValueError):
    """No candidate preset parsed the sample; an explicit format is required."""

    def __init__(self) -> None:
        super().__init__("interrupted:format_unmatched")
        self.code = "interrupted:format_unmatched"


def _pattern_for(candidate: str):
    return _combined._PRESET_RES[candidate]


def _looks_apache_escaped(line: str) -> bool:
    return '\\"' in line or "\\\\" in line


def detect_lines(
    lines: list[bytes],
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
) -> DetectResult:
    """Score candidate presets over a bounded sample of raw lines."""
    limits = limits or Limits()
    sample = [raw for raw in lines[:sample_lines] if raw.strip()]
    if not sample:
        raise UnmatchedFormat()
    scores: dict[str, int] = {}
    for candidate in _CANDIDATE_ORDER:
        pattern = _pattern_for(candidate)
        hits = 0
        for raw in sample:
            if len(raw) > limits.max_line_bytes:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if pattern.match(text) is not None:
                hits += 1
        scores[candidate] = hits
    total = len(sample)
    # Combined Nginx/Apache share a grammar and differ only in escapes: an
    # observed escape decides, otherwise both stay joint candidates.
    apache_escape_seen = any(
        _looks_apache_escaped(raw.decode("utf-8", errors="replace")) for raw in sample
    )
    ranked = sorted(scores.items(), key=lambda item: (-item[1], _CANDIDATE_ORDER.index(item[0])))
    best, best_hits = ranked[0]
    confidence = best_hits / total
    if best_hits == 0:
        raise UnmatchedFormat()
    # Combined Nginx/Apache share one grammar and differ only in escapes:
    # without an observed escape they are indistinguishable, so both stay
    # joint candidates and detection fails closed. An observed escape
    # removes the Nginx twin from contention before margins are computed.
    if apache_escape_seen:
        ranked = [entry for entry in ranked if entry[0] != _combined.NGINX_COMBINED]
        best, best_hits = ranked[0]
        confidence = best_hits / total
    if (
        scores[_combined.NGINX_COMBINED] == scores[_combined.APACHE_COMBINED] > 0
        and not apache_escape_seen
    ):
        return DetectResult(
            format_id=None,
            confidence=confidence,
            candidates=(_combined.NGINX_COMBINED, _combined.APACHE_COMBINED),
            ambiguous=True,
            samples=total,
        )
    runner_hits = ranked[1][1]
    margin = (best_hits - runner_hits) / total
    if confidence < MIN_CONFIDENCE or margin < MIN_MARGIN:
        close = tuple(name for name, hits in ranked if hits == best_hits)
        if len(close) < 2:
            close = (ranked[0][0], ranked[1][0]) if ranked[1][1] > 0 else (ranked[0][0],)
        return DetectResult(
            format_id=None,
            confidence=confidence,
            candidates=close,
            ambiguous=True,
            samples=total,
        )
    return DetectResult(
        format_id=best, confidence=confidence, candidates=(best,), ambiguous=False, samples=total
    )


def detect_sample_lines(
    path: Path,
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
) -> DetectResult:
    """Detect a format from plain bytes. Gzip sources use ``detect_path``."""
    with open(path, "rb") as stream:
        data = stream.read(sample_lines * (limits.max_line_bytes if limits else 65536))
    return detect_lines(data.split(b"\n"), limits=limits, sample_lines=sample_lines)


def detect_path(
    path: Path,
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
    gzip_limits=None,
) -> DetectResult:
    """Detect a format from a source path, transparently handling gzip."""
    from app.ingestion.gzipio import has_gzip_magic, iter_decompressed_chunks

    if not has_gzip_magic(path):
        return detect_sample_lines(path, limits=limits, sample_lines=sample_lines)
    chunks, _stats = iter_decompressed_chunks(path, limits=gzip_limits)
    buffered = bytearray()
    needed = sample_lines * 4096
    for data in chunks:
        buffered += data
        if len(buffered) >= needed:
            break
    return detect_lines(bytes(buffered).split(b"\n"), limits=limits, sample_lines=sample_lines)


def resolve_format(
    format_id: str,
    path: Path,
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
    gzip_limits=None,
) -> str:
    """Resolve ``auto`` through sampled detection; concrete IDs pass through."""
    if format_id != _combined.AUTO:
        return format_id
    result = detect_path(path, limits=limits, sample_lines=sample_lines, gzip_limits=gzip_limits)
    if result.ambiguous or result.format_id is None:
        raise AmbiguousFormat(result.candidates, result.confidence)
    return result.format_id

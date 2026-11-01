"""Sampled format autodetection with bounded confidence (T1a).

Detection never guesses silently: each candidate preset scores the fraction
of sampled lines it genuinely parses (bounded ``parse_line`` validity, not
just regex shape), and the winner must clear both an absolute confidence
floor and a margin over the runner-up. Otherwise detection reports
``ambiguous`` (or ``unmatched`` when nothing parses) and the caller must
require an explicit ``--format`` override. Richer grammars win ties:
Extended is tried before vhost before Combined before Common, and an
Apache escape observation prefers the Apache Combined variant.

The Nginx/Apache Combined twins share one grammar, so sampling cannot tell
server software apart: without an observed escape they resolve to the
configured ``default_combined`` flavor instead of failing every ordinary
file. The decision still reports both candidates honestly. Only genuinely
different or mixed formats fail closed on ambiguity.
"""

from dataclasses import dataclass
from pathlib import Path

from app.ingestion import combined as _combined
from app.ingestion.combined import CombinedRecord, Limits

MIN_CONFIDENCE = 0.8
MIN_MARGIN = 0.2
DEFAULT_SAMPLE_LINES = 32
# Hard ceilings on the detection sample: line counts above this are
# rejected, and buffered sample bytes never exceed this even on gzip.
MAX_SAMPLE_LINES = 1024
MAX_SAMPLE_BYTES = 4 * 1024 * 1024
# Fixed probe key for validity scoring. Detection input is synthetic and
# the pseudonyms are never persisted; any non-empty key scores the same.
_PROBE_HMAC_KEY = b"logcarve-autodetect-probe"

_CANDIDATE_ORDER = (
    _combined.NGINX_EXTENDED,
    _combined.APACHE_VHOST_COMBINED,
    _combined.NGINX_COMBINED,
    _combined.APACHE_COMBINED,
    _combined.COMMON,
)
_COMBINED_TWINS = frozenset({_combined.NGINX_COMBINED, _combined.APACHE_COMBINED})


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


def _looks_apache_escaped(line: str) -> bool:
    return '\\"' in line or "\\\\" in line


def _check_sample_args(sample_lines: int, default_combined: str) -> None:
    """Reject non-finite/non-integer/absurd sample sizes and unknown defaults."""
    if (
        isinstance(sample_lines, bool)
        or not isinstance(sample_lines, int)
        or not 1 <= sample_lines <= MAX_SAMPLE_LINES
    ):
        raise ValueError(f"sample_lines must be an integer in 1..{MAX_SAMPLE_LINES}")
    if default_combined not in (_combined.NGINX_COMBINED, _combined.APACHE_COMBINED):
        raise ValueError(f"unknown default_combined: {default_combined!r}")


def detect_lines(
    lines: list[bytes],
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
    default_combined: str = _combined.NGINX_COMBINED,
) -> DetectResult:
    """Score candidate presets over a bounded sample of raw lines.

    Scores count lines each preset genuinely parses (bounded
    ``parse_line`` validity: grammar, escapes, timing, MIME, host), not
    mere regex shape. The indistinguishable Combined twins resolve to
    ``default_combined`` (the configured server flavor) with both
    candidates reported; only genuinely different or mixed formats fail
    closed on ambiguity.
    """
    _check_sample_args(sample_lines, default_combined)
    limits = limits or Limits()
    sample = [raw for raw in lines[:sample_lines] if raw.strip()]
    if not sample:
        raise UnmatchedFormat()
    scores: dict[str, int] = {}
    for candidate in _CANDIDATE_ORDER:
        hits = 0
        for raw in sample:
            if len(raw) > limits.max_line_bytes:
                continue
            item = _combined.parse_line(
                raw,
                source_id="autodetect",
                format_id=candidate,
                hmac_key=_PROBE_HMAC_KEY,
                limits=limits,
            )
            if isinstance(item, CombinedRecord):
                hits += 1
        scores[candidate] = hits
    total = len(sample)
    # Combined Nginx/Apache share a grammar and differ only in escapes: an
    # observed escape decides for Apache, otherwise the twins resolve to
    # the configured default instead of failing every ordinary file.
    apache_escape_seen = any(
        _looks_apache_escaped(raw.decode("utf-8", errors="replace")) for raw in sample
    )
    # The twins shortcut only fires when they strictly lead the field:
    # a third grammar scoring alongside them means genuinely mixed input,
    # which still fails closed below.
    others_best = max(hits for name, hits in scores.items() if name not in _COMBINED_TWINS)
    twins_hits = scores[_combined.NGINX_COMBINED]
    if twins_hits == scores[_combined.APACHE_COMBINED] > others_best and not apache_escape_seen:
        # The twins share one grammar, so they score as one Combined
        # family against genuinely different grammars — but the family
        # still clears the same confidence floor and margin as every
        # other candidate. Otherwise low-confidence or mixed samples
        # (e.g. mostly invalid lines, or Combined mixed with Common)
        # would bypass the gates through this shortcut.
        confidence = twins_hits / total
        margin = (twins_hits - others_best) / total
        if confidence < MIN_CONFIDENCE or margin < MIN_MARGIN:
            close = (_combined.NGINX_COMBINED, _combined.APACHE_COMBINED)
            if others_best > 0:
                third = max(
                    (name for name in _CANDIDATE_ORDER if name not in _COMBINED_TWINS),
                    key=lambda name: (scores[name], -_CANDIDATE_ORDER.index(name)),
                )
                if scores[third] > 0:
                    close = (_combined.NGINX_COMBINED, _combined.APACHE_COMBINED, third)
            return DetectResult(
                format_id=None,
                confidence=confidence,
                candidates=close,
                ambiguous=True,
                samples=total,
            )
        return DetectResult(
            format_id=default_combined,
            confidence=confidence,
            candidates=(_combined.NGINX_COMBINED, _combined.APACHE_COMBINED),
            ambiguous=False,
            samples=total,
        )
    ranked = sorted(scores.items(), key=lambda item: (-item[1], _CANDIDATE_ORDER.index(item[0])))
    # An observed escape removes the Nginx twin from contention before
    # margins are computed.
    if apache_escape_seen:
        ranked = [entry for entry in ranked if entry[0] != _combined.NGINX_COMBINED]
    best, best_hits = ranked[0]
    confidence = best_hits / total
    if best_hits == 0:
        raise UnmatchedFormat()
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
    default_combined: str = _combined.NGINX_COMBINED,
) -> DetectResult:
    """Detect a format from plain bytes. Gzip sources use ``detect_path``.

    At most ``MAX_SAMPLE_BYTES`` are ever buffered, even when the
    configured line cap times the sample count exceeds it.
    """
    _check_sample_args(sample_lines, default_combined)
    cap = limits.max_line_bytes if limits else 65536
    with open(path, "rb") as stream:
        data = stream.read(min(sample_lines * cap, MAX_SAMPLE_BYTES))
    return detect_lines(
        data.split(b"\n"),
        limits=limits,
        sample_lines=sample_lines,
        default_combined=default_combined,
    )


def detect_path(
    path: Path,
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
    default_combined: str = _combined.NGINX_COMBINED,
    gzip_limits=None,
) -> DetectResult:
    """Detect a format from a source path, transparently handling gzip.

    The buffered decompressed sample never exceeds ``MAX_SAMPLE_BYTES``;
    long or empty samples cannot grow the buffer or the work without bound.
    """
    from app.ingestion.gzipio import has_gzip_magic, iter_decompressed_chunks

    _check_sample_args(sample_lines, default_combined)
    if not has_gzip_magic(path):
        return detect_sample_lines(
            path, limits=limits, sample_lines=sample_lines, default_combined=default_combined
        )
    chunks, _stats = iter_decompressed_chunks(path, limits=gzip_limits)
    buffered = bytearray()
    needed = min(sample_lines * 4096, MAX_SAMPLE_BYTES)
    for data in chunks:
        buffered += data
        if len(buffered) >= needed:
            break
    return detect_lines(
        bytes(buffered).split(b"\n"),
        limits=limits,
        sample_lines=sample_lines,
        default_combined=default_combined,
    )


def resolve_format(
    format_id: str,
    path: Path,
    *,
    limits: Limits | None = None,
    sample_lines: int = DEFAULT_SAMPLE_LINES,
    default_combined: str = _combined.NGINX_COMBINED,
    gzip_limits=None,
) -> str:
    """Resolve ``auto`` through sampled detection; concrete IDs pass through.

    ``default_combined`` is the configured server flavor used when the
    Combined twins tie without an escape observation.
    """
    if format_id != _combined.AUTO:
        return format_id
    _check_sample_args(sample_lines, default_combined)
    result = detect_path(
        path,
        limits=limits,
        sample_lines=sample_lines,
        default_combined=default_combined,
        gzip_limits=gzip_limits,
    )
    if result.ambiguous or result.format_id is None:
        raise AmbiguousFormat(result.candidates, result.confidence)
    return result.format_id

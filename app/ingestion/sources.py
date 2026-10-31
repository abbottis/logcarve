"""Administrative source resolution (T2).

Sources are configured by the administrator as ``SourceConfig`` values
and resolved server-side: only relative paths inside an approved root
are accepted. Absolute paths, parent-directory traversal and symlinks
that escape the approved root are rejected. Files are opened read-only;
import state and checkpoints belong to LogCarve storage (a later slice),
never to the source tree.
"""

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from app.ingestion.combined import PRESETS


class SourceError(ValueError):
    """Unsafe or unusable source configuration."""


class SourceConfig(BaseModel):
    """Administrator-configured log source. Never client-controlled."""

    source_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    format_id: str
    allowed_root: Path
    relative_path: str = Field(min_length=1, max_length=1024)

    @field_validator("format_id")
    @classmethod
    def _known_preset(cls, value: str) -> str:
        if value not in PRESETS:
            raise ValueError(f"unknown format_id: {value!r}")
        return value

    @field_validator("allowed_root")
    @classmethod
    def _absolute_root(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("allowed_root must be absolute")
        return value

    @field_validator("relative_path")
    @classmethod
    def _relative_only(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("relative_path must not contain NUL")
        pure = Path(value)
        if pure.is_absolute() or value.startswith("~"):
            raise ValueError("relative_path must be relative")
        if ".." in pure.parts:
            raise ValueError("relative_path must not traverse upwards")
        return value


@dataclass(frozen=True)
class FileIdentity:
    """File identity for later replay handling (device + inode + size + mtime)."""

    dev: int
    ino: int
    size: int
    mtime_ns: int


def resolve_source_path(config: SourceConfig) -> Path:
    """Resolve a configured source to a real file inside its approved root.

    The final resolved path (symlinks followed) must stay inside the
    resolved approved root, and the target must be a regular file.
    """
    root = config.allowed_root.resolve()
    if not root.is_dir():
        raise SourceError(f"allowed_root is not a directory: {root}")
    candidate = (root / config.relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise SourceError(f"source escapes its approved root: {config.relative_path!r}")
    if not candidate.is_file():
        raise SourceError(f"source is not a regular file: {candidate}")
    return candidate


def identify_file(path: Path) -> FileIdentity:
    """Capture file identity without reading file contents."""
    stat = path.stat()
    return FileIdentity(
        dev=stat.st_dev, ino=stat.st_ino, size=stat.st_size, mtime_ns=stat.st_mtime_ns
    )


def open_source_log(path: Path):
    """Open a resolved source read-only as a binary stream."""
    return open(path, "rb")

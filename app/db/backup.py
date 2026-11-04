"""Online backup, restore and rotation for the SQLite store (T3).

Backups use SQLite's online backup API, which produces a consistent
snapshot without blocking readers longer than a checkpoint and without
copying a live WAL file by hand.

Safety rules: inputs must already exist as valid SQLite files and are
opened read-only, so a missing or invalid input fails before any file
is created. Destinations are created exclusively (no overwrite) with
owner-only (0600) permissions from the start, and an incomplete owned
output is removed if the operation fails. Rotation only touches
recognized LogCarve backups of the intended database; unrelated files,
other backup sets and symlinks are preserved. Expiry policy and the
backup-before-migration procedure are documented in
``docs/backup-restore.md``.
"""

import os
import sqlite3
from pathlib import Path

BACKUP_SUFFIX = ".sqlite3"
BACKUP_MODE = 0o600


def _require_existing_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {path}")


def _check_integrity(path: Path) -> None:
    """Integrity check over a read-only handle; never creates the file."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"not a valid SQLite database: {path}: {exc}") from exc
    finally:
        conn.close()
    if [row[0] for row in rows] != ["ok"]:
        raise ValueError(f"integrity check failed for {path}: {rows!r}")


def _create_exclusive(path: Path) -> None:
    """Create ``path`` exclusively with owner-only permissions from the start."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, BACKUP_MODE)
    except FileExistsError:
        raise FileExistsError(f"refusing to overwrite: {path}") from None
    os.close(fd)


def _copy_online(source_path: Path, dest_path: Path) -> None:
    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        target = sqlite3.connect(str(dest_path))
        try:
            with target:
                source.backup(target)
        finally:
            target.close()
    finally:
        source.close()


def backup_database(db_path: Path, dest_path: Path) -> Path:
    """Copy ``db_path`` to ``dest_path`` with a consistent online snapshot."""
    db_path = Path(db_path)
    dest_path = Path(dest_path)
    _require_existing_file(db_path, "source database")
    _check_integrity(db_path)
    _create_exclusive(dest_path)
    try:
        _copy_online(db_path, dest_path)
        _check_integrity(dest_path)
    except BaseException:
        dest_path.unlink(missing_ok=True)
        raise
    os.chmod(dest_path, BACKUP_MODE)
    return dest_path


def restore_database(backup_path: Path, dest_path: Path) -> Path:
    """Restore a backup into an isolated destination path (never a live DB)."""
    backup_path = Path(backup_path)
    dest_path = Path(dest_path)
    _require_existing_file(backup_path, "backup file")
    _check_integrity(backup_path)
    _create_exclusive(dest_path)
    try:
        _copy_online(backup_path, dest_path)
        _check_integrity(dest_path)
    except BaseException:
        dest_path.unlink(missing_ok=True)
        raise
    os.chmod(dest_path, BACKUP_MODE)
    return dest_path


def _is_recognized_backup(name: str, db_stem: str) -> bool:
    """Only LogCarve-managed names for this database: ``<stem>-backup-*.sqlite3``."""
    if not name.endswith(BACKUP_SUFFIX):
        return False
    stem = name[: -len(BACKUP_SUFFIX)]
    rest = stem[len(db_stem) + len("-") :] if stem.startswith(db_stem + "-") else None
    if rest is None:
        return False
    return rest.startswith(("backup-", "pre-migrate-"))


def rotate_backups(backup_dir: Path, *, keep: int, db_stem: str) -> list[Path]:
    """Delete all but the newest ``keep`` recognized backups of ``db_stem``.

    Unrelated files, other databases' backups and symlinks are preserved;
    only regular files with a recognized name are candidates.
    """
    if keep < 1:
        raise ValueError("keep must be at least 1")
    if not db_stem:
        raise ValueError("db_stem must be non-empty")
    candidates = sorted(
        (
            p
            for p in Path(backup_dir).iterdir()
            if p.is_file() and not p.is_symlink() and _is_recognized_backup(p.name, db_stem)
        ),
        key=lambda p: p.stat().st_mtime_ns,
    )
    removed = candidates[: max(0, len(candidates) - keep)]
    for path in removed:
        path.unlink()
    return removed

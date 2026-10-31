"""T3 backup tests: online snapshots, permissions, restore isolation, rotation."""

import sqlite3
import stat as statmod

import pytest

from app.db.backup import backup_database, restore_database, rotate_backups
from app.db.database import connect
from app.db.migrations_runner import migrate


def _seeded_db(path):
    migrate(path)
    conn = connect(path)
    with conn:
        conn.execute(
            "INSERT INTO sites (id, name, hostname, timezone, created_at) VALUES (?, ?, ?, ?, ?)",
            ("default", "Example site", "example.org", "UTC", "2026-10-29T00:00:00+00:00"),
        )
    conn.close()
    return path


def _mode(path) -> int:
    return statmod.S_IMODE(path.stat().st_mode)


def test_backup_snapshot_and_permissions(tmp_path):
    db = _seeded_db(tmp_path / "live.sqlite3")
    dest = tmp_path / "backups" / "snap.sqlite3"
    out = backup_database(db, dest)
    assert out == dest and dest.is_file()
    assert _mode(dest) == 0o600
    probe = sqlite3.connect(str(dest))
    try:
        assert probe.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert probe.execute("SELECT id FROM sites").fetchall() == [("default",)]
    finally:
        probe.close()


def test_backup_refuses_overwrite(tmp_path):
    db = _seeded_db(tmp_path / "live.sqlite3")
    dest = tmp_path / "snap.sqlite3"
    dest.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        backup_database(db, dest)
    assert dest.read_bytes() == b"existing"


def test_restore_into_isolated_path(tmp_path):
    db = _seeded_db(tmp_path / "live.sqlite3")
    backup = backup_database(db, tmp_path / "backups" / "snap.sqlite3")
    dest = tmp_path / "isolated" / "restored.sqlite3"
    out = restore_database(backup, dest)
    assert out == dest
    assert _mode(dest) == 0o600
    probe = sqlite3.connect(str(dest))
    try:
        assert probe.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert probe.execute("SELECT COUNT(*) FROM sites").fetchone() == (1,)
    finally:
        probe.close()
    with pytest.raises(FileExistsError):
        restore_database(backup, dest)


def test_rotate_backups_keeps_newest(tmp_path):
    import time

    names = []
    for tag in ("a-old", "b-mid", "c-new"):
        path = tmp_path / f"live-backup-{tag}.sqlite3"
        path.write_bytes(b"x")
        names.append(path)
        time.sleep(0.01)
    removed = rotate_backups(tmp_path, keep=2, db_stem="live")
    assert removed == names[:1]
    assert names[1].is_file() and names[2].is_file()
    with pytest.raises(ValueError):
        rotate_backups(tmp_path, keep=0, db_stem="live")
    with pytest.raises(ValueError):
        rotate_backups(tmp_path, keep=2, db_stem="")


def test_rotate_preserves_unrelated_other_db_and_symlinks(tmp_path):
    import time

    (tmp_path / "notes.sqlite3").write_text("unrelated")
    (tmp_path / "otherdb-backup-old.sqlite3").write_bytes(b"x")
    target = tmp_path / "mydb-pre-migrate-old.sqlite3"
    target.write_bytes(b"x")
    time.sleep(0.01)
    kept = []
    for tag in ("old", "new"):
        path = tmp_path / f"mydb-backup-{tag}.sqlite3"
        path.write_bytes(b"x")
        kept.append(path)
        time.sleep(0.01)
    link = tmp_path / "mydb-backup-link.sqlite3"
    link.symlink_to(kept[0])
    removed = rotate_backups(tmp_path, keep=1, db_stem="mydb")
    assert sorted(p.name for p in removed) == [
        "mydb-backup-old.sqlite3",
        "mydb-pre-migrate-old.sqlite3",
    ]
    assert (tmp_path / "notes.sqlite3").is_file()
    assert (tmp_path / "otherdb-backup-old.sqlite3").is_file()
    assert link.is_symlink()
    assert kept[1].is_file()


def test_backup_missing_source_fails_without_creating_files(tmp_path):
    dest = tmp_path / "out.sqlite3"
    with pytest.raises(FileNotFoundError):
        backup_database(tmp_path / "missing.sqlite3", dest)
    assert not dest.exists()


def test_backup_invalid_source_fails_without_creating_files(tmp_path):
    bogus = tmp_path / "bogus.sqlite3"
    bogus.write_text("not a database")
    dest = tmp_path / "out.sqlite3"
    with pytest.raises(ValueError, match="[Nn]ot a valid|integrity"):
        backup_database(bogus, dest)
    assert not dest.exists()


def test_restore_missing_backup_fails_without_creating_files(tmp_path):
    dest = tmp_path / "restored.sqlite3"
    with pytest.raises(FileNotFoundError):
        restore_database(tmp_path / "nobackup.sqlite3", dest)
    assert not dest.exists()


def test_restore_invalid_backup_fails_without_creating_files(tmp_path):
    bogus = tmp_path / "bogus.sqlite3"
    bogus.write_text("not a database")
    dest = tmp_path / "restored.sqlite3"
    with pytest.raises(ValueError, match="[Nn]ot a valid|integrity"):
        restore_database(bogus, dest)
    assert not dest.exists()

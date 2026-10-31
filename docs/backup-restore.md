# Backup, restore and retention procedures

All paths below are operator-chosen local filesystem locations. Backups,
databases and generated logs stay outside version control (see
`.gitignore`: `*.sqlite*`, `*.db*`, `/backups/`, `/data/`).

## Online backup

Use the administrative CLI (SQLite online backup API; consistent
snapshot, no live WAL file copy):

```bash
HMAC_KEY="$(cat /run/secrets/hmac_key)" \
python -m app.db.cli --db /data/logcarve.sqlite3 backup \
  --dest-dir /backups/logcarve --keep 7
```

Backup files are created exclusively (no overwrite) with owner-only
(`0600`) permissions from the start and `<db>-backup-<UTC stamp>.sqlite3`
names. `--keep N` rotates the directory down to the newest N backups
**of that database only**: rotation recognizes `<stem>-backup-*.sqlite3`
and `<stem>-pre-migrate-*.sqlite3` regular files and preserves
unrelated files, other databases' backups and symlinks. Inputs must
already exist as valid SQLite files and are opened read-only; a
missing or invalid input fails before any file is created, and an
incomplete owned output is removed on failure.

## Rotation and expiry

- Keep at least 7 daily backups; keep one monthly backup for 12 months
  (move it aside before rotation prunes the daily directory).
- Expiry means deleting the backup file; live records are unaffected.
- Never restore over a live database file. Restore always targets an
  isolated path, then passes integrity, record and retention checks
  before any operator decision about promotion.

## Restore (isolated) with retention reapplied

```bash
python -m app.db.cli --db /data/restored.sqlite3 restore \
  --backup /backups/logcarve/logcarve-backup-<stamp>.sqlite3 \
  --dest /data/restored.sqlite3 --retention-days 30
```

The restore command verifies backup integrity before copying,
re-verifies the destination afterwards, and reapplies the configured
UTC event retention when `--retention-days` is given. After restoring,
confirm expected record counts and analytics coverage before serving.

## Backup before migrations

`migrate()` accepts a backup directory and takes a timestamped online
backup first whenever migrations are pending on a non-empty database:

```python
from pathlib import Path
from app.db.migrations_runner import migrate

result = migrate(Path("/data/logcarve.sqlite3"), backup_dir=Path("/backups/logcarve"))
print(result.applied, result.backup_path)
```

Downgrades are not supported: restore the pre-migration backup into an
isolated path if a migration must be undone.

## Retention

```bash
python -m app.db.cli --db /data/logcarve.sqlite3 retention --days 30
```

Retention deletes only LogCarve-owned normalized `requests` rows older
than the UTC cutoff. Source logs are never touched; import reports are
kept. A replay after retention re-inserts deleted rows as new records.

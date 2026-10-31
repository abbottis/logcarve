# Database rules

Read the root rules, `docs/architecture.md` and DB criteria in `docs/acceptance-criteria.md`.

- Use SQLite WAL on local persistent storage; coordinate one writer and transactional batch imports.
- Keep schema evolution explicit and versioned in `migrations/`; document backup before migrations.
- Initial domain tables come from spec §2.5; add auth storage only with a documented concrete need.
- Persist nullable durations and normalized UTC timestamps with explicit conventions.
- Index measured queries; begin with timestamp, status, path, bot family and source.
- Parameterize values; allowlist selectable identifiers and sort columns rather than interpolating client SQL.
- Keep repository logic free of model/network calls and transport-specific dependencies.
- Retention affects only imported events and related LogCarve-owned data; never follow a source path to delete logs.
- Test migration, rollback/recovery behavior, restart persistence, integrity and restore using temporary synthetic DBs.
- Never commit SQLite files, WAL/SHM sidecars, backups or real database exports.

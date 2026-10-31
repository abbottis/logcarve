# Ingestion rules

Read the root rules, `docs/log-formats.md` and ING criteria in `docs/acceptance-criteria.md`.

- Support NCSA Combined from Nginx and Apache first; require explicit source presets.
- Stream bytes/lines with bounded memory, batches and bounded diagnostic excerpts.
- Handle quotes/escapes, IPv4/IPv6, invalid bytes, missing `-` fields and unusual request lines.
- Define limits for line, target and User-Agent sizes; account for every rejected/truncated record.
- Preserve original offset in source context while normalizing timestamps to UTC.
- Separate request path from query; remove query values and secret-bearing fields before persistence.
- Never retain whole raw lines as routine application data or diagnostics.
- Resolve configured `source_id` values server-side; validate allowed roots and symlink targets.
- Read source files without altering them; import status/checkpoints belong to LogCarve storage.
- Make replay idempotent using import/file identity and record position, preserving legitimate identical requests.
- Do not deduplicate solely by normalized event content.
- Count accepted/rejected lines and expose format, size, duration and coverage in the import report.
- Missing timing is nullable; Common, custom timing, gzip and incremental rotation handling remain later work.
- Add synthetic parser fixtures with independent expected values before claiming format compatibility.
- Parser/security boundary changes require independent review before release.

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
- Missing timing stays nullable; it is never presented as zero latency.
- Accepted exception 2026-11-01 (ADR 0003, implemented across parity stages T1–T5): gzip, Common/Apache-vhost/Nginx-Extended presets, measured-timing presets, bounded admin custom format mappings, and opt-in incremental follow/rotation (follow/rotation recorded under stage T5). No browser import UI.
- Add synthetic parser fixtures with independent expected values before claiming format compatibility.
- Parser/security boundary changes require independent review before release.

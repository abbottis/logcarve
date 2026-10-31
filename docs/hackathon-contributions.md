# Hackathon contributions and provenance

The supplied spec identifies the prior LogWerk project and requires transparent separation of reused work from LogCarve contributions created from 2026-10-26 onward. This file records source provenance and development contributions; it does not certify event eligibility.

| Date | Contribution | Origin | Status/evidence |
| --- | --- | --- | --- |
| 2026-10-28 | Directory scaffold, project instructions, four project skills and derived planning/configuration docs | New LogCarve preparation from supplied v0.4 spec and official Muse docs | Local files; no application behavior claimed |
| 2026-10-28 | `docs/technical-spec.md` | Owner-supplied German specification v0.4 | Unmodified snapshot; checksum in `spec-provenance.md` |
| 2026-10-31 | External client `findings` route correction and verification | New original LogCarve change implemented with AI assistance at the owner's request; no LogWerk import | Existing real-HTTP tests pass; full suite 137 passed in clean and conflicting environments; see `verification.md` |

No LogWerk code, assets or rule datasets have been imported. The application uses third-party dependencies and browser assets listed in `THIRD_PARTY_NOTICES.md`; their licenses and notices remain applicable. Before each import, record source URL, commit/version, destination, license/notices, what predates the event and what changes are new. Keep the public demo/submission wording consistent with this record.

Before submission: independently review the current Official Rules, verify eligibility/prior-work requirements and prepare the actual demonstration. Original LogCarve code and documentation are licensed Apache-2.0; third-party components retain their own licenses. Credit terms and an API balance do not establish submission eligibility or account access. Publishing a repository or submitting material has not been authorized by this scaffold task.

## Development checkpoint, 1 November 2026

The backend, deterministic analytics, authentication/API, bounded assistant,
browser dashboard and local demo were developed under owner direction with
AI-assisted implementation and independent verification. Muse Code was used
for the implementation workflow. This record makes no exclusive-tool or
sole-manual-authorship claim.

- Original implementation: parser, SQLite import/replay/backup/retention,
  shared analytics, scoped API, bounded model tools and local browser UI.
- Third-party code/assets: the pinned packages and retained notices in
  `THIRD_PARTY_NOTICES.md`; no LogWerk imports.
- Actual verification: 341 unit/integration tests, 15 browser E2E tests,
  28 container-browser cases and 23 isolated container smoke checks passed
  at the development checkpoint. See `verification.md` for environments
  and historical results.
- Authorized real model test: two investigations completed with evidence;
  the third stopped at its context bound. AI-02 remains incomplete and
  native Linux x86-64 installation remains unverified.
- Publication: a consolidated checkpoint branch preserves the existing
  remote main as its parent. Detailed development branches remain local;
  the publication commit is not a claim that all work occurred in one step.

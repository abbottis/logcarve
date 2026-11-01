# Hackathon contributions and provenance

The supplied spec identifies the prior LogWerk project and requires transparent separation of reused work from LogCarve contributions created from 2026-10-26 onward. This file records source provenance and development contributions; it does not certify event eligibility.

| Date | Contribution | Origin | Status/evidence |
| --- | --- | --- | --- |
| 2026-10-28 | Directory scaffold, project instructions, four project skills and derived planning/configuration docs | New LogCarve preparation from supplied v0.4 spec and official Muse docs | Local files; no application behavior claimed |
| 2026-10-28 | `docs/technical-spec.md` | Owner-supplied German specification v0.4 | Unmodified snapshot; checksum in `spec-provenance.md` |
| 2026-10-31 | External client `findings` route correction and verification | New original LogCarve change implemented with AI assistance at the owner's request; no LogWerk import | Existing real-HTTP tests pass; full suite 137 passed in clean and conflicting environments; see `verification.md` |
| 2026-11-01 | Bot rule catalog v3: 70 LogWerk `botRules` patterns/names/provider-purpose labels adapted (pinned commit `d7ab01c`, MIT retained verbatim in `THIRD_PARTY_NOTICES.md`), 5 pre-existing LogCarve rule IDs kept, 2 original rules added (UptimeRobot monitoring, generic suspected-automation fallback); category/ordering/matcher remaps are new LogCarve work | Mixed adaptation with AI assistance at the owner's request; no LogWerk application code, session/person inference or sample data | `config/bot_rules.yaml` v3 (77 entries); see Slice A evidence in `verification.md` |
| 2026-11-01 | Analytics completion slices A/B/C on `feature/traffic-analytics` (clean `e81d2d0`): traffic classification, scoped API and trusted assistant filters; rich dashboard panels with traffic/bot controls, sortable bot drilldowns and sanitized request explorer; combined 120-row synthetic demo dataset with probe/seeder and isolated candidate procedure | New LogCarve work implemented with AI assistance at the owner's request plus independent AI-assisted planning, review and testing; no LogWerk application code | Independently verified per `verification.md`: 428 unit/integration, 22 E2E, 53/53 API probe, 8/0 candidate Compose, 24/0 offline smoke, 32-case browser matrix |
| 2026-11-01 | Acceptance-readiness corrections at `bb272a9` on `feature/acceptance-polish-2026-11-01`: display-timezone catalogue (A), three offline AI evidence/cost/citation corrections (B), source-change quality on every tool plus decoded scope validation (C); this documentation closeout | New LogCarve work implemented with AI assistance at the owner's request plus independent verification; no LogWerk application code | Independently verified per `verification.md`: 480 unit/integration, 24 E2E, 121-check offline probe, 599-zone catalogue, 8/0 candidate Compose, 24/0 offline smoke, 32-case browser matrix; Muse implementation with separate AI-assisted planning, review and testing — no exclusive authorship claim |
| 2026-11-01 | Owner-UX Stage B on `feature/owner-ux-review-2026-11-01`: 8-column sortable Requests overview with per-row details, original conflicting-bot-identity candidate (`sec-conflicting-bot-identity` v1, explicit 9-token set, security ruleset v2, bot catalog 77 unchanged), largest-responses retarget, plus the five Stage A coordinator fixes | New original LogCarve work implemented with AI assistance at the owner's request; no LogWerk import, no application code copied | `config/security_rules.yaml` v2, `app/analytics/conflict.py`, shared query/service/API/dashboard path; 529 unit/integration pass per `verification.md`; E2E/browser + Docker proofs pending coordinator |

No LogWerk application code, assets, session/person inference or sample data have been imported. The 70 adapted rule-catalog patterns are recorded above and in `THIRD_PARTY_NOTICES.md` with the retained MIT notice. The application otherwise uses third-party dependencies and browser assets listed in `THIRD_PARTY_NOTICES.md`; their licenses and notices remain applicable. Before each import, record source URL, commit/version, destination, license/notices, what predates the event and what changes are new. Keep the public demo/submission wording consistent with this record.

Before submission: independently review the current Official Rules, verify eligibility/prior-work requirements and prepare the actual demonstration. Original LogCarve code and documentation are licensed Apache-2.0; third-party components retain their own licenses. Credit terms and an API balance do not establish submission eligibility or account access. Publishing a repository or submitting material has not been authorized by this scaffold task.

## Analytics closeout, 1 November 2026

The backend, deterministic analytics, authentication/API, bounded assistant,
browser dashboard and local demo were developed under owner direction:
Muse implementation with separate AI-assisted planning, review and testing.

- Original implementation: parser, SQLite import/replay/backup/retention,
  shared analytics, scoped API, bounded model tools, local browser UI,
  and the traffic-analytics slices (classification, dashboard panels,
  bot drilldowns, request explorer, 120-row synthetic demo).
- Third-party code/assets: the pinned packages and retained notices in
  `THIRD_PARTY_NOTICES.md`; no LogWerk application-code imports (the
  70-pattern rule adaptation of 2026-11-01 is recorded separately above
  with the pinned commit and retained MIT notice).
- Actual verification at clean `e81d2d0`: 428 unit/integration tests, 22
  browser E2E tests, a 53/53 synthetic API probe, 8/0 candidate Compose
  run, 24/0 offline smoke and a 32-case browser matrix passed per the
  independent runner. See `verification.md` for environments and
  historical results.
- Authorized real model test: two investigations completed with evidence;
  the third stopped at its context bound. AI-02 remains incomplete and
  native Linux x86-64 installation remains unverified.
- Publication: a consolidated checkpoint branch preserves the existing
  remote main as its parent. Detailed development branches remain local;
  the publication commit is not a claim that all work occurred in one step.

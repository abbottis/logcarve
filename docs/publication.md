# Publication checkpoint — 1 November 2026

## Scope

`publication/local-demo-2026-11-01` is a consolidated review snapshot based
on the existing remote `main`. It does not publish the local development
commit graph. Original development branches and their detailed evidence
remain local and unchanged; the snapshot is not a claim that development
occurred in one step.

Internal tool-specific wording is expressed as implementation, review and
local verification roles. Contribution and third-party provenance remain
truthful; no exclusive-tool authorship is claimed. See
[hackathon contributions](hackathon-contributions.md).

## Included and excluded

The branch contains application and test source, pinned manifests,
synthetic fixtures, locally bundled browser assets and their notices,
project instructions, plans and verification documentation. Project and
bundled-component license texts are also included in the container image.

Secrets, personal settings, databases, actual logs, session exports,
provider traces, local browser binaries and detailed local artifacts are
excluded. Paths in authored documentation use generic checkout locations.
The supplied specification snapshot and upstream copyright/license texts
are preserved.

## Evidence and limits

This snapshot carries the tested application source from the development
checkpoint: 341 unit/integration tests, 15 protected-browser E2E tests,
28 container-browser cases and 23 isolated container smoke checks passed.
Publishing changes documentation and license packaging; it does not repair
or expand product behavior. Packaging checks are appended to
[verification](verification.md).

Known open work: context minimization for the third real investigation,
returned cost-display aggregation and citation wording. Two real cases
completed; the third stopped at its bound. Native Linux x86-64 installation
is NOT RUN. No release or submission approval is implied.

No additional inference, account change, production deployment, application
exposure or merge to `main` is part of this publication. Existing real-run
usage and the exhausted investigation allowance must not be reset or
recreated to obtain retries.

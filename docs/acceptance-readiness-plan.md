# Acceptance readiness plan (2026-11-01)

Owner-authorized bounded fixes on clean `5ff5f22`, branch
`feature/acceptance-polish-2026-11-01`. Sole writer, exact model
`muse-spark-1.3-contributor`/medium, Contributor ON for public source +
synthetic fixtures only. Sandbox, approval judge, CSP, browser
protections and product Standard fail-closed egress stay unchanged. No
provider/product calls, pushes, `main` merge, production deployment,
extra dependencies or unrelated features. No inspection of
parent/private runtime, secrets, traces, tokens, real usage or model
keys. No Docker/socket/private demo commands in this task.

## Stage A — implement NOW (this task)

Display timezone completeness, default and sorting (UI-01, UI-02, UI-05).

1. Replace the hardcoded `UTC`/`Europe/Berlin` list in `app/web/routes.py`
   and `partials/filter_bar.html` with the cached server-available IANA
   catalogue (`stdlib zoneinfo.available_timezones`). All supported keys
   retained, validated server-side. No external geo/network,
   browser-location guessing or new third-party assets/dependencies.
   Installed tz DB already verified in-environment (598 keys, including
   `Asia/Kathmandu`, `Australia/Adelaide`, `America/New_York`,
   `Pacific/Auckland`, `Asia/Tokyo`).
2. Readability and stable sorting: configured server default and UTC
   discoverable first (default first, UTC next unless identical), remaining
   regions alphabetically with city/zone names alphabetical within region,
   readable labels (underscores replaced, exact IANA values preserved).
   No duplicate values; aliases kept as listed, not silently discarded.
   Native accessible keyboard selection; no custom widget.
3. Precedence: explicit valid `tz` in URL wins; absent `tz` uses validated
   `DEFAULT_TIMEZONE` configuration (demo: `Europe/Berlin`). A reliable
   local server IANA name is accepted only as an exact installed key
   (operator `TZ` environment); abbreviations and fixed offsets never
   identify a region and are never guessed. Unknown zones fail safely
   (`error.bad_params`). UTC storage, UTC time bounds, existing query
   roundtrip/nav/settings/evidence URLs and public API UTC contract
   unchanged.
4. Cache the catalogue (no `available_timezones` file enumeration per
   request); safe deterministic UTC fallback when the zone DB or config is
   absent/broken. Validate `Settings.default_timezone` (valid installed
   IANA key) without breaking clean/conflicting-env hermetic isolation and
   without weakening existing settings validation.
5. Selected zone renders real table and timeline times. Representative
   zones from all regions, fractional offsets (`Asia/Kathmandu`,
   `Australia/Adelaide`), DST (`America/New_York`), `Pacific/Auckland`;
   truthful unavailable heatmap for unsupported fractional-offset cases, no
   invented counts. No analytics scope expansion.
6. Central `en` locale/docs/settings guidance updates only as needed;
   product strings stay English. No unrelated asset changes; build authored
   assets only if changed and inspect generated diffs.
7. Tests: catalogue completeness/order/default/explicit
   override/invalid-input/no-path-injection plus real display preservation
   across Apply/nav/reload (integration). Maintained repeatable protected
   Playwright coverage for native select default/explicit Asian/Pacific
   zones, both themes/narrow as relevant (`chromium_sandbox=True`; sandbox
   denial is reported, never weakened). Focused locked tests + Ruff; actual
   outcomes and missing browser/Docker checks recorded in
   `docs/verification.md`.

Done when: A is committed on this branch with plan/tests/docs, tree clean,
stopped for independent reinspection before stage B.

## Stage B — later, do NOT implement in this task

Three offline-only AI corrections (owner will accept with corrections):

1. 4000-char history minimization preserving typed scope/metadata.
2. Displayed estimated cost double count vs correct settled ledger.
3. Explicit evidence citations and observation/window wording.

Preserve ALL CAPS and exhausted real allowance; independent review before
local demo update.

## Stage C — local regression, safe backup, image, acceptance

Local regression, safe backup, exact-image update, owner acceptance/video
rehearsal. No claim that paid/live gates passed.

## Status 2026-11-01 — closeout: A + B + C complete, owner acceptance pending

Timezone catalogue (A), three offline AI corrections (B) and the
tiny readiness fix — completed source-change quality on every tool
plus decoded scope validation before JSON escaping — are committed
at clean application source `bb272a9` on
`feature/acceptance-polish-2026-11-01` (canonical equivalent
`ad6d74f` on `local/acceptance-readiness-2026-11-01`; inspect `git
status` rather than assuming a branch name). Independent final
gates are recorded in `docs/verification.md` (append-only
transcription): 480 unit/integration, 24 protected E2E, 121-check
offline mock probe, semantic evidence checks, 599-zone catalogue,
Gitleaks (only the known false positive), 8/0 candidate Compose,
24/0 offline smoke, 32-case browser matrix on candidate and
persistent demo, 7/7 timezone acceptance on both, exact-image demo
update with the 8080 demo left running. No `main` merge, production
deployment, paid call, cap change or dependency added. Prior
incomplete real AI demo and no-new-paid-call status retained.
Remaining for the owner: manual acceptance TODAY (see
`docs/acceptance-checklist.md`, record on Tue 03 Nov), then video
rehearsal/publication only after owner feedback and audit; real AI
proof only with a new explicit bounded authorization; Linux x86-64
verification for a full install claim. No new GitHub push yet; the
old publication checkpoint remains older and `main` is unchanged.

## Status 2026-11-01 (earlier) — Stage A correction + Stage B implemented

Separate owner authorization (Stage B task, same sole-writer branch
`feature/acceptance-polish-2026-11-01`): the two independent
protected-Chromium timezone findings were fixed first as commit
`773cd12` (OOB timezone-notice update, real narrow-menu nav,
cached config validation, TZ fallback reachability, abbreviation
guards, tzdata fail-fast honesty; 18 timezone integration tests),
then all three AI corrections above as a second commit (bounded
evidence projection shared by fake/native paths, exact settled cost
display, citations/observation wording + matcher scope fix; new
18-test offline Stage B suite, full unit/integration green).
Evidence: `docs/verification.md` (append-only). Remaining gaps for
the coordinator/next session: protected-Chromium E2E execution
(timezone + slice suites), Docker/candidate/smoke runs, x86-64
verification, independent reinspection of both commits, owner
acceptance/video rehearsal. No `main` merge, production deployment,
paid call, cap change or dependency added. Prior incomplete real AI
demo and no-new-paid-call status retained.

# Acceptance checklist — owner review (2 Nov 2026 checkpoint, historical)

Short practical checklist for the owner review. The 2 Nov 2026
parity-activated demo checkpoint below (code anchor `84f440f`, live
8080 at schema 8, 120 rows) is historical; the current documented
state lives in [current status](current-status.md) and the evidence
in [verification](verification.md). Earlier acceptance-readiness
anchor `bb272a9` (reviewed public source branch
`feature/acceptance-polish-2026-11-01`) remains the historical record.
Inspect `git status` rather than assuming a branch name. Record
expected, actual and issues per row; nothing here auto-accepts on the
owner's behalf.

## Demo access

- Fixed 120-row window:
  `http://127.0.0.1:8080/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined`
- Log in as `demo-admin`. The password lives only in the protected
  local password file (see `docs/demo.md` for the exact location);
  it is never committed, printed or pasted. No actual secret is
  recorded here or anywhere in version control.

## Expected checkpoints

| # | Area | Expected | Actual | Issue |
| --- | --- | --- | --- | --- |
| 1 | Overview totals | 120 requests, 28 client errors (4xx), 3 server errors (5xx), 127744 known bytes | | |
| 2 | Traffic shares | 48 browser-like / 45 claimed bot / 18 automation / 9 unknown | | |
| 3 | Named bots | GPT filter selects 16 requests; bot sorting, detail drilldown and paging agree | | |
| 4 | Errors view | Old 27 Oct 14:00–15:00 UTC window returns 10 requests, including the missing page (5) and referrer groups 3+2 | | |
| 5 | Requests explorer | Sanitized values, stable sorting, paging | | |
| 6 | Timezones | Full 599-zone list in the tested image; configured Europe/Berlin first, UTC next; readable regional order; explicit Auckland/Kathmandu Apply, nav and reload with real converted times and stable UTC scope | | |
| 7 | Heatmap honesty | Fractional-offset zones show the explicit unavailable state, never invented counts | | |
| 8 | Themes/layouts | Light + dark, desktop + mobile (390px), no overflow, console or failed-response errors | | |
| 9 | External API | Independent stdlib client works with AI off (summary/crawlers/findings) | | |

## AI state (read honestly)

- Current UI/demo: AI OFF (disabled, empty model key) on the normal bridge network — it makes no provider calls but is NOT air-gapped. The offline proof is the separate internal-network smoke (see `docs/demo.md`).
- Historical real Meta smoke: 2 of 3 investigations completed with
  evidence; the third failed closed at its context bound. AI-02
  stays INCOMPLETE; the third case was not rerun.
- Offline scripted proof of the corrected evidence/cost/citation
  behavior is NOT a live Meta proof.

## Three-minute video rehearsal (outline, not a recording)

Uses only the actual local data and features above plus the
independently usable API. No recording has been made; no full
AI-02 pass, submission, official-rules review or production release
is claimed.

- 0:00–0:40 — Fixed window Overview: 120 / 28 / 3 / 127744 totals.
- 0:40–1:20 — Traffic shares 48/45/18/9; claimed-bot filter;
  GPT-16 drilldown with sorting and paging.
- 1:20–1:50 — Errors view (old 27 Oct window, missing page,
  referrers 3+2); sanitized Requests explorer.
- 1:50–2:20 — Timezone switch Berlin → Auckland/Kathmandu with
  Apply/nav/reload and honest fractional heatmap state.
- 2:20–2:45 — Terminal: independent stdlib API client run with AI off.
- 2:45–3:00 — Honest AI state (UI AI-off; 2 real successes, third
  not rerun; offline proof is not live proof) and pending gates.

## Remaining decisions and gates before final submission

- [ ] Owner corrections/acceptance from this review.
- [ ] Real AI proof, only if desired, with a new explicit bounded
  authorization (no allowance reset, recreate or restore).
- [ ] Linux x86-64 verification for a full install claim.
- [ ] Current Official Rules and materials check, then actual
  recording and publication.
- Deferred scope (sessions, webhooks, MCP, shipped
  translations, browser file-import UI) stays out. Parity gzip/custom
  formats, follow/rotation, GeoIP, saved views, comparison windows and
  full-result export are implemented and locally activated (see
  `docs/verification.md` final receipts), not deferred.
- No merge to `main`, production deployment, GitHub push or public
  exposure without explicit owner approval. `main` is unchanged;
  never publish the canonical private graph blindly.

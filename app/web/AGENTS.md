# Web and asset rules

Read the root rules and UI criteria in `docs/acceptance-criteria.md`.
These conventions also guide `assets/` and `config/locales/` changes via the root instructions.

- Render with Jinja2/semantic HTML and progressive htmx; keep business metrics in analytics.
- Autoescape all log-derived text; render model responses through a safe explicit policy.
- Build Tailwind 4/daisyUI 5 locally; bundle htmx/Chart.js 4, fonts and SVG icons locally.
- Keep authored sources in `assets/src/` and served output in `app/web/static/`.
- Retain asset/font licenses and provenance; avoid runtime CDN or remote font requests.
- Use central English locale keys; include errors, starter questions and accessible labels.
- Use semantic theme tokens and Tailwind standard colors from spec §3.4.
- Honor system light/dark preference, allow a persisted override and prevent wrong-theme flash.
- Keep scripts external and compatible with CSP `self`; do not require unsafe-inline/eval.
- Paginate/filter/sort large tables server-side and preserve safe filter URL state.
- Show timezone, coverage, incomplete imports and unavailable duration visibly.
- Provide a data-table alternative for charts, keyboard navigation, visible focus and WCAG 2.1 AA targets.
- Display claimed bots and investigation candidates with their limitations.
- Starter questions populate the input; send only on a clear user action.
- Check narrow/desktop layouts, both themes and console/network behavior with synthetic data.
- Run repeatable Playwright core-path tests; screenshots alone do not establish correctness.

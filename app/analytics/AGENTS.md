# Analytics rules

Read the root rules and ANA criteria in `docs/acceptance-criteria.md`.

- Own the common deterministic metrics used by web views, REST handlers and model tools.
- Accept validated query/filter objects and use parameterized repository queries.
- Define bucket/time boundaries and deterministic sorting, including equal-count tie-breakers.
- Return coverage, rejected-line quality, filters and sample size alongside aggregates.
- Preserve missing values: absent duration cannot contribute zeroes to latency percentiles.
- Version bot/security rules and retain the rule reference needed to explain a classification.
- Bot-family matching proves a User-Agent claim only; no verified identity without a separate verification path.
- Findings are investigation candidates, never proof of compromise or attribution.
- Do not infer sessions, unique people, rankings, indexation or conversions from request counts.
- Use small hand-verifiable fixture totals; dashboard, API and AI tools must agree for the same filters.

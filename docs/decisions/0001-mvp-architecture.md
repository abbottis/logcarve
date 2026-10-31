# ADR 0001 — MVP architecture

- Date: 2026-10-28
- Status: **Proposed**
- Origin: supplied technical spec v0.4, §§0–8 and 13
- Acceptance impact: ING, DB, ANA, API, AI, UI and OPS criteria

## Context

The hackathon scope requires a small self-hosted product with explainable log metrics, a real Meta assistant and a separately usable external analytics API. Safe source access and privacy are baseline constraints. No implementation exists in this checkout.

## Proposal

Use Python 3.12+, FastAPI/Pydantic, SQLite WAL and parameterized repositories. Support NCSA Combined from Nginx/Apache for one site/source. Reuse deterministic analytics in API, dashboard and internal tools. Render Jinja2/htmx with build-time Tailwind 4/daisyUI 5 and local Chart.js/fonts. Ship via non-root Docker Compose behind TLS. Use Meta Spark 1.3 through a server-side verified Standard adapter and bounded tools.

Keep external API reads independent of the assistant. Do not add a production Node service, SPA, Redis/PostgreSQL, persistent agent team, product MCP server or webhooks for the initial slice.

## Consequences and open points

This minimizes moving parts but requires deliberate SQLite writer coordination, indexing and measurement. Missing timing limits latency analysis. Auth schema, source/import identity, finding persistence, exact dependencies, license/provenance and actual provider/account policy still need review. See the decision register.

## Acceptance record

No acceptance has been recorded. Use `/plan` and `/grill` to present the concrete first slice; append the owner's decision/reference here before implementing architecture choices that require approval.

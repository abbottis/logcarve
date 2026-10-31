# Privacy and data egress

Status: planned controls and verification gates from the supplied spec, not a legal or operational compliance claim.

## Default local handling

Source logs remain read-only on administrator-approved roots. Parse locally and retain only needed normalized events. Discard query values; minimize Referer to domain/approved path; mask sensitive path/UA content; use secret HMAC pseudonyms. Delete only LogCarve-owned imported data according to configured retention. Use synthetic data in development/CI/demos.

Pseudonymization does not automatically anonymize data. Before real deployments, the operator must resolve the applicable legal basis, provider agreements, retention, locations and transfer requirements. The supplied spec's policy/credit statements are inputs to reverify at use, not an account check performed by this scaffold.

## Outbound model boundary

Before **every** provider call, validate allowed provider/model and independently verified effective service tier, authorize site/time scope, minimize payload fields, sanitize identifiers/secrets and enforce work/budget limits. Cover prompt/history, tool results, retries, caches and replay. Default export is metrics, time ranges, rule references and sanitized evidence.

Real-data transmission is blocked for Contributor, unknown tier, unverified provider or a policy switch. `--contributor-mode off` and `MODEL_SERVICE_TIER=standard` express intent only; they do not prove account/service handling. Standard service is not blanket privacy approval. Until checks are documented, only synthetic/nonconfidential data may be sent. Do not expose sensitive project context via coding-agent tools or retained history.

The optional Open-weight identifier `meta-models/muse-spark-open-1026` has no verified provider/base URL/data policy here. It receives a separate adapter, key, budget and approval gate if adopted.

## Separate data consumers

The external REST API returns minimized authorized analytics without any Meta key or inference proxy. Its client/operator is responsible for any onward transfer to another model provider. The independent API remains available with chat disabled or over budget. Administrative import and retention have separate permissions.

Model errors and telemetry must not log prompts, raw logs or credentials by default. Record safe usage metadata. A local English disabled/error state explains blocked inference; deterministic analytics stay online.

Test evidence: PRIV-01–03, API-04 and COST-02 in `acceptance-criteria.md`. Public end-user/region/age requirements and current provider terms must be checked before expanding the private deployment scope; no such release is performed here.

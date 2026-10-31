# Log format contract

Target MVP: one explicit **NCSA Combined** source preset, with Nginx and Apache fixtures tested against the same normalized expectations. No error-log compatibility claim.

Synthetic reference:

```text
203.0.113.20 - - [27/Oct/2026:10:15:32 +0100] "GET /missing-page HTTP/1.1" 404 153 "https://example.org/old-link" "ExampleCrawler/1.0"
```

Expected time: `2026-10-27T09:15:32Z`, original offset `+0100`; path `/missing-page`, status 404, bytes 153, Referer host `example.org`. Duration is absent and must remain `null`. Client identity becomes an HMAC pseudonym using a test-only key, never a plain IP hash.

Normalize timestamp/offset, method, request target/path, HTTP version, status, response bytes, sanitized Referer/User-Agent, source/site, client pseudonym and optional duration. Split/discard query values before persistence. Do not persist the raw reference line as product data.

Required fixture variants: IPv4/IPv6, escaped quotes, unusual whitespace/request lines, HTTP/2, missing `-`, invalid bytes, timezone changes, malformed/oversized input, missing referrer/UA, 404/5xx/429, declared/spoofed crawlers, sensitive paths and adversarial instructions in all attacker-controlled fields.

Reject invalid lines with bounded masked diagnostics and accurate accounting. Replay must not duplicate records; identical legitimate requests must remain distinct. Source identity/offset strategy needs explicit tests.

Timing extensions are later work: Nginx seconds → milliseconds; Apache `%D` microseconds → milliseconds, `%{ms}T` already milliseconds. Common, gzip, JSONL, LiteSpeed and custom Plesk formats require new presets/fixtures before claiming support. Default Combined has no latency measurement.

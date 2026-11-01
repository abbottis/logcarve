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

## T1a parity presets (2026-11-01, PAR-01)

- `common`: Common Log Format without Referer/User-Agent. Grammar-disjoint
  from Combined, so neither is ever mislabelled as the other.
- `apache_vhost_combined`: `%v` server hostname followed by Combined
  (Apache escapes apply). `other.example`-style foreign hosts are skipped
  as valid foreign lines, never counted as the configured site.
- `nginx_extended`: Combined prefixed with the server host and suffixed
  with six measured fields: `cache` (`$upstream_cache_status`),
  `request_time` (seconds → ms), `mime` (`$sent_http_content_type`,
  `type/subtype`, optional `;params` without spaces), `tls`
  (`$ssl_protocol`), and quoted `upstream_response_time` (seconds → ms,
  summed when multi-valued with an explicit component count).
- Referer handling adds a minimized path (`/old` from
  `https://example.org/old?x=1`, scheme kept only for http/https,
  credentials dropped, secrets masked) next to the existing host.
- Measured timing normalizes to milliseconds; absent stays `None`
  (never `0`); present-but-invalid rejects the line (`invalid_timing`,
  `invalid_mime`, `invalid_cache`, `invalid_tls`, `invalid_host`
  are explicit reason codes).
- gzip sources are detected by magic bytes (`1f 8b`), never the
  extension, and stream within compressed/uncompressed/ratio/member
  bounds; truncated/CRC/member-limit breaches map to fixed
  `interrupted:gzip_*` codes. Identity is logical (decompressed) bytes,
  so the same plaintext imported plain or gzipped replays.
- `auto` format resolves per file through sampled detection with
  bounded confidence; Nginx/Apache Combined ties fail closed unless an
  escape observation or an explicit `--format` decides. Administrator
  custom mappings (`custom-*` JSON) are validated to nesting-free safe
  regex constructs with required/allowed named fields and explicit
  timing units; no eval, no code, no unbounded backtracking.

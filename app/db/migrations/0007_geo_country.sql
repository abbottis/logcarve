-- 0007: T5a nullable offline-country enrichment (PAR-09).
-- Genuine local MMDB country lookup (DB-IP Country Lite format)
-- derived transiently at import/reprocess time from the validated
-- client address, before the raw address is discarded or encrypted.
-- Only a safe ISO 3166-1 alpha-2 code plus the lookup
-- source/release/status needed for honest coverage is stored:
-- original addresses never land here. New columns stay NULL on
-- legacy rows until an explicit read-only source reprocess enriches
-- them; core event identity (ids, fingerprint/offset, HMAC
-- pseudonyms), legacy duration_ms, auth tables, model usage and
-- allowance rows are untouched.

-- ISO country code when the lookup hit, NULL for Unknown (lookup
-- ran but yielded no country, address not globally routable, or
-- never looked up).
ALTER TABLE requests ADD COLUMN country_code TEXT;
-- Lookup source label (for example 'dbip-country-lite'), NULL when
-- the lookup did not run or the database was unavailable.
ALTER TABLE requests ADD COLUMN geo_source TEXT;
-- Database release the lookup read (YYYY-MM from the database
-- build epoch), NULL when unavailable or never looked up.
ALTER TABLE requests ADD COLUMN geo_release TEXT;
-- Per-row lookup outcome: 'hit', 'unknown' or 'unavailable'; NULL
-- on legacy rows that predate the lookup.
ALTER TABLE requests ADD COLUMN geo_status TEXT;

CREATE INDEX IF NOT EXISTS idx_requests_country ON requests (country_code);

-- 0008: T5b2 opt-in follow/checkpoint state (PAR-08).
--
-- Live-follow generations, durable checkpoints and per-batch accounting
-- for the bounded CLI follow command. This state is LogCarve-owned
-- progress metadata only: offsets, digests, generation identity,
-- aggregate counts and the unfinished-oversized-line discard marker
-- (a flag plus the physical line start offset). Raw line bytes, pending
-- chunks, URLs, User-Agents, original addresses and keys are NEVER
-- persisted here (partial lines are re-read from the approved read-only
-- source after a restart; an unfinished oversized prefix re-enters drop
-- mode through the persisted marker, never through stored bytes).
--
-- Follow event rows in `requests` carry a generation fingerprint label
-- (`follow:v1:<source>:<seq>`, see app/db/follow.py), honestly
-- distinguished from full-file content hashes: it names the consuming
-- generation, never the current file digest. Each generation (and each
-- archive replay) owns exactly one `imports` attempt row, so empty polls
-- create no history rows while coverage aggregates stay exact. Batch
-- logical-SHA/offset replay identity is untouched.

CREATE TABLE IF NOT EXISTS follow_generations (
  source_id TEXT NOT NULL,
  generation_seq INTEGER NOT NULL,
  generation_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  file_dev INTEGER NOT NULL,
  file_ino INTEGER NOT NULL,
  gen_start_offset INTEGER NOT NULL,
  next_offset INTEGER NOT NULL,
  next_line_number INTEGER NOT NULL,
  oversized_active INTEGER NOT NULL DEFAULT 0,
  oversized_start INTEGER,
  consumed_sha256 TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_mtime_ns INTEGER NOT NULL,
  adopted_prefix_sha TEXT,
  adopted_import_id INTEGER,
  fresh_start INTEGER NOT NULL DEFAULT 0,
  import_id INTEGER,
  status TEXT NOT NULL,
  detail TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (source_id, generation_seq)
);

CREATE TABLE IF NOT EXISTS follow_batches (
  id INTEGER PRIMARY KEY,
  source_id TEXT NOT NULL,
  generation_seq INTEGER NOT NULL,
  start_offset INTEGER NOT NULL,
  end_offset INTEGER NOT NULL,
  lines_accepted INTEGER NOT NULL,
  lines_rejected INTEGER NOT NULL,
  lines_skipped_foreign INTEGER NOT NULL,
  records_inserted INTEGER NOT NULL,
  records_replayed INTEGER NOT NULL,
  consumed_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_follow_batches_source
  ON follow_batches (source_id, generation_seq);

-- Phase 1.2: make the audit log tamper-evident.
--
-- audit_log was a plain append table, so anyone with database access could
-- delete or rewrite rows and leave no trace. Each entry now carries the hash
-- of the entry before it, so an edit, deletion or reordering breaks the chain
-- at that point and at every point after it.
--
-- Rows written before this migration are left with seq NULL. Chaining cannot
-- retroactively protect entries that were never chained, and backfilling
-- hashes over them would manufacture an integrity claim that was never true.
-- The chain therefore starts at the first entry written after this runs, and
-- verification covers seq IS NOT NULL.

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq        BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash  TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS audit_log_seq_key ON audit_log (seq) WHERE seq IS NOT NULL;

-- A checkpoint signed by the control key lets a verifier validate everything
-- through through_seq from a single signature, and makes truncation of the
-- tail detectable rather than merely internally consistent.
CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id             BIGSERIAL PRIMARY KEY,
  at             TIMESTAMPTZ NOT NULL,
  through_seq    BIGINT      NOT NULL,
  entry_hash     TEXT        NOT NULL,
  signing_key_id TEXT        NOT NULL DEFAULT '',
  signature      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_checkpoints_seq_idx ON audit_checkpoints (through_seq DESC);

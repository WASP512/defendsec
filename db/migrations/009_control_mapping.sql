-- Phase 1.7: control mapping as a data model, not a report.
--
-- Records carry the framework controls they speak to at the moment they are
-- written. A report generated later can only work from whatever the database
-- happens to hold; a tag written at creation time is what was true then,
-- which is the honest answer for a period that has already closed.
--
-- Two columns per record type:
--   signal      — what DefendSec observed, in terms that survive a framework
--                 revision. This is the durable fact.
--   control_ids — the identifiers that signal resolved to when the record was
--                 written. Redundant with the mapping on purpose: it lets an
--                 assessor's query hit an index instead of replaying the
--                 mapping across a year of history, and it does not silently
--                 change when the mapping is revised.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS signal      TEXT   NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS control_ids TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE commands  ADD COLUMN IF NOT EXISTS signal      TEXT   NOT NULL DEFAULT '';
ALTER TABLE commands  ADD COLUMN IF NOT EXISTS control_ids TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS signal      TEXT   NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS control_ids TEXT[] NOT NULL DEFAULT '{}';

-- GIN indexes: the compliance view's central query is "every record touching
-- this control in this window", which is a containment test over the array.
CREATE INDEX IF NOT EXISTS alerts_control_ids_idx    ON alerts    USING GIN (control_ids);
CREATE INDEX IF NOT EXISTS commands_control_ids_idx  ON commands  USING GIN (control_ids);
CREATE INDEX IF NOT EXISTS audit_log_control_ids_idx ON audit_log USING GIN (control_ids);

-- Rows written before this migration keep an empty tag. Backfilling them by
-- re-running today's mapping over old records would manufacture a claim that
-- the tag existed at the time, which is the same mistake the audit chain
-- migration declined to make.

-- The catalog is materialised from the Go registry on startup so it can be
-- joined in SQL, but the registry remains the single source of truth: this
-- table is rebuilt from it, never edited in place.
CREATE TABLE IF NOT EXISTS control_catalog (
  id           TEXT PRIMARY KEY,
  framework    TEXT   NOT NULL,
  control      TEXT   NOT NULL,
  title        TEXT   NOT NULL,
  family       TEXT   NOT NULL DEFAULT '',
  coverage     TEXT   NOT NULL,
  note         TEXT   NOT NULL DEFAULT '',
  signals      TEXT[] NOT NULL DEFAULT '{}',
  derived_from TEXT[] NOT NULL DEFAULT '{}',
  synced_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS control_catalog_framework_idx ON control_catalog (framework);
CREATE INDEX IF NOT EXISTS control_catalog_coverage_idx  ON control_catalog (coverage);

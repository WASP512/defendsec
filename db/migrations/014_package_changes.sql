-- Phase 4.3: package change history, for triage assistance.
--
-- Software inventory was a JSONB snapshot overwritten on every heartbeat, so
-- the question triage actually needs — "did anything upgrade this package, and
-- when?" — had no answer in stored data. A file-integrity alert could only ever
-- be reported as "this file changed", never as "this file changed because
-- openssh-server was upgraded four minutes earlier".
--
-- Version transitions are recorded here as they are observed. This is also the
-- answer to a compliance question that was previously unanswerable: when was
-- this host actually patched, as opposed to when did it last report updates
-- available.
CREATE TABLE IF NOT EXISTS package_changes (
  id          TEXT PRIMARY KEY,
  device_id   TEXT        NOT NULL,
  hostname    TEXT        NOT NULL DEFAULT '',
  package     TEXT        NOT NULL,
  -- Empty previous_version means the package appeared; empty new_version
  -- means it was removed. Both are recorded: a package disappearing from a
  -- host is as interesting as one arriving, and more interesting if nobody
  -- meant it to.
  previous_version TEXT   NOT NULL DEFAULT '',
  new_version      TEXT   NOT NULL DEFAULT '',
  -- observed_at is when DefendSec noticed, not when the upgrade happened.
  -- Inventory arrives on a heartbeat interval, so the real change is
  -- somewhere in the preceding window. Naming the column for what it
  -- actually holds keeps anything built on it from implying precision that
  -- is not there.
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Triage looks up "changes to this host around this time", so the index
-- matches that shape rather than being per-column.
CREATE INDEX IF NOT EXISTS package_changes_device_observed_idx
  ON package_changes (device_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS package_changes_package_idx
  ON package_changes (package);

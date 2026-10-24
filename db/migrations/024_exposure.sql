-- Exposure view (slice 5): how a finding closed, and the history a trend needs.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- Why a finding is closed. The matcher closes a finding when a run no longer
-- confirms it; that alone does not say whether the host got the fix. When the
-- host's inventory is at hand the store records which it was:
--   fixed               the package is installed at or above the fixed version
--   package_removed     the package is no longer installed
--   no_longer_affected  the package is still there below the fixed version (or
--                       the finding had no fix), but the advisory data no longer
--                       lists it: a feed reclassified or withdrew it
--   ''                  closed before this column existed, or without inventory
-- resolved_installed is the version the host had when the finding closed.
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS resolution TEXT NOT NULL DEFAULT ''
  CHECK (resolution IN ('', 'fixed', 'package_removed', 'no_longer_affected'));
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS resolved_installed TEXT NOT NULL DEFAULT '';

-- The date Red Hat shipped the fix behind an awaiting_vendor finding, so the
-- watch list can say "fixed by Red Hat on 2026-10-22; awaiting Rocky". NULL for
-- every other kind, and for erratum dates a feed does not give.
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS upstream_fixed_on DATE;

-- vuln_findings keeps one row per (host, advisory, package family) and, when a
-- closed finding comes back, restarts first_seen. The interval that ended is
-- copied here first, so "open on date A, closed on date B" and the trendline
-- both survive a recurrence.
CREATE TABLE IF NOT EXISTS vuln_finding_intervals (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL,
  family      TEXT NOT NULL,
  kind        TEXT NOT NULL,
  kev         BOOLEAN NOT NULL DEFAULT false,
  opened_at   TIMESTAMPTZ NOT NULL,
  closed_at   TIMESTAMPTZ NOT NULL,
  resolution  TEXT NOT NULL DEFAULT '',
  UNIQUE (device_id, advisory_id, family, opened_at)
);
CREATE INDEX IF NOT EXISTS vuln_finding_intervals_window_idx
  ON vuln_finding_intervals (opened_at, closed_at);

-- The exposure list groups open findings by advisory and bucket.
CREATE INDEX IF NOT EXISTS vuln_findings_open_kind_idx
  ON vuln_findings (kind, advisory_id) WHERE resolved_at IS NULL;

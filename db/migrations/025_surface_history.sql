-- Surface findings in the exposure view (slice 7b): the history a trend and a
-- signed export need.
--
-- surface_findings keeps one row per (asset, finding, subject) and, until now,
-- a finding that closed and later came back simply had resolved_at cleared and
-- kept its first first_seen, so the days it was closed counted as open. Like
-- vuln_finding_intervals, the interval that ended is copied here when the row
-- reopens and first_seen restarts, so "open on date A, closed on date B" and
-- the trendline survive a recurrence.
--
-- Rows reopened before this migration already lost the closed gap; nothing can
-- recover it, and the trend caveats say so.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

CREATE TABLE IF NOT EXISTS surface_finding_intervals (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id   BIGINT NOT NULL REFERENCES surface_assets(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  subject    TEXT NOT NULL DEFAULT '',
  severity   TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  opened_at  TIMESTAMPTZ NOT NULL,
  closed_at  TIMESTAMPTZ NOT NULL,
  UNIQUE (asset_id, finding_id, subject, opened_at)
);

CREATE INDEX IF NOT EXISTS surface_finding_intervals_window_idx
  ON surface_finding_intervals (opened_at, closed_at);

-- The exposure list ranks open and resolved findings; the trend reads spans.
CREATE INDEX IF NOT EXISTS surface_findings_span_idx
  ON surface_findings (first_seen, resolved_at);

-- The findings a scan opened or closed, kept with the scan so its digest (see
-- internal/evidence/surface.go) can be recomputed at export time and compared
-- with the chained audit entry written when the scan was stored. Scans stored
-- before this migration have no entry in the chain and are exported as
-- unattested.
ALTER TABLE surface_scans ADD COLUMN IF NOT EXISTS changes JSONB NOT NULL DEFAULT '[]'::jsonb;

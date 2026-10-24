-- Distro-aware matcher storage (slice 4).
--
-- The matcher compares a host's packages with the distro's own advisory ranges
-- and records what it found here. Every statement is idempotent: migration
-- files re-run on every start (see migrations.go).

-- Which feed loaded a range. Findings quote it ("ubuntu-jammy"); the feed's
-- fetch date comes from the range's snapshot. Ranges loaded before this column
-- existed read '' until their feed is next reloaded; the matcher then labels
-- them with the distro and release instead.
ALTER TABLE advisory_ranges ADD COLUMN IF NOT EXISTS feed TEXT NOT NULL DEFAULT '';

-- What the agent reports about the host's packaging: os-release ID and
-- VERSION_ID, and the package manager. They choose the feed and the version
-- ordering. Empty for agents older than this matcher and for Windows.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS distro TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS distro_release TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS package_manager TEXT NOT NULL DEFAULT '';

-- One row per (host, advisory, package family): a source package that builds
-- ten binaries is one finding. Rows are never deleted when a finding goes away:
-- resolved_at is set, so "open on date A, closed on date B" stays answerable.
-- If the finding comes back the row is reopened and first_seen is kept.
--
-- range_id and snapshot_id are evidence, not live references: advisory ranges
-- are replaced wholesale on every feed sync, so range_id names the range as it
-- was when the finding was last confirmed and is deliberately not a foreign key.
-- snapshot_id is, because snapshots are never removed.
CREATE TABLE IF NOT EXISTS vuln_findings (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  advisory_id    TEXT NOT NULL,
  family         TEXT NOT NULL,
  range_id       BIGINT,
  snapshot_id    BIGINT REFERENCES feed_snapshots(id),
  feed           TEXT NOT NULL DEFAULT '',
  feed_date      TIMESTAMPTZ,
  kind           TEXT NOT NULL CHECK (kind IN ('finding', 'informational')),
  basis          TEXT NOT NULL CHECK (basis IN ('distro', 'upstream')),
  package        TEXT NOT NULL,
  source_package TEXT NOT NULL DEFAULT '',
  installed      TEXT NOT NULL,
  fixed          TEXT NOT NULL DEFAULT '',
  fix_state      TEXT NOT NULL,
  cve            TEXT NOT NULL DEFAULT '',
  severity       TEXT NOT NULL DEFAULT 'unknown',
  summary        TEXT NOT NULL DEFAULT '',
  kev            BOOLEAN NOT NULL DEFAULT false,
  epss           NUMERIC,
  cvss_score     NUMERIC,
  reason         TEXT NOT NULL DEFAULT '',
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at    TIMESTAMPTZ,
  UNIQUE (device_id, advisory_id, family)
);

CREATE INDEX IF NOT EXISTS vuln_findings_open_idx
  ON vuln_findings (device_id) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS vuln_findings_advisory_idx ON vuln_findings (advisory_id);

-- What the last match run for a host examined. A host with no findings is only
-- clean if coverage is 'covered': 'no_feed' (distro known, no feed loaded for
-- that release) and 'no_distro' (agent did not report one) mean it was not
-- really assessed.
CREATE TABLE IF NOT EXISTS host_vuln_state (
  device_id     TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  distro        TEXT NOT NULL DEFAULT '',
  release       TEXT NOT NULL DEFAULT '',
  coverage      TEXT NOT NULL CHECK (coverage IN ('covered', 'no_feed', 'no_distro')),
  packages      INTEGER NOT NULL DEFAULT 0,
  distro_mapped INTEGER NOT NULL DEFAULT 0,
  upstream      INTEGER NOT NULL DEFAULT 0,
  undecidable   INTEGER NOT NULL DEFAULT 0,
  not_affected  INTEGER NOT NULL DEFAULT 0,
  snapshot_id   BIGINT REFERENCES feed_snapshots(id),
  matched_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

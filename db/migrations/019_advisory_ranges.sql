-- Exposure-management advisory model (roadmap Phase 0.4, slice 2).
--
-- The single-floor model, advisories(package, below), cannot say "fixed in
-- 1.1.1k on one branch and 3.0.2 on another", cannot say which distro release
-- a fixed version belongs to, and cannot say "will not fix" or "not affected".
-- This migration adds:
--
--   feed_snapshots   one row per sync: which feeds, fetched when, which digest.
--                    Findings reference a snapshot so they can be reproduced.
--   advisories       gains CVSS, CWE, CISA KEV, EPSS and the snapshot it came
--                    from. `package` and `below` are kept, defaulted to '', so
--                    the current matcher and scripts/ingest-osv.py keep working
--                    until the distro-aware matcher (slice 4) replaces them.
--   advisory_ranges  zero or more affected ranges per advisory, with a
--                    (distro, release) dimension and a fix state.
--
-- Every migration file is re-run on each start (see migrations.go), so every
-- statement here is idempotent. It applies the same way to a fresh database
-- and to one that already holds advisories rows.

CREATE TABLE IF NOT EXISTS feed_snapshots (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- [{"name","url","fetched_at","sha256","record_count"}]
  feeds      JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(feeds) = 'array')
);

ALTER TABLE advisories ADD COLUMN IF NOT EXISTS cvss_vector TEXT NOT NULL DEFAULT '';
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS cvss_score  NUMERIC CHECK (cvss_score >= 0 AND cvss_score <= 10);
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS cwe         TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS kev         BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS kev_added   DATE;
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS epss        NUMERIC CHECK (epss >= 0 AND epss <= 1);
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS epss_date   DATE;
ALTER TABLE advisories ADD COLUMN IF NOT EXISTS snapshot_id BIGINT REFERENCES feed_snapshots(id);

-- Advisories written in the new shape carry their versions in advisory_ranges
-- and leave the legacy single-floor columns empty.
ALTER TABLE advisories ALTER COLUMN package SET DEFAULT '';
ALTER TABLE advisories ALTER COLUMN below   SET DEFAULT '';

CREATE TABLE IF NOT EXISTS advisory_ranges (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  advisory_id    TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  -- OSV-style ecosystem ("Debian", "Ubuntu", "Red Hat", "npm", ...). The
  -- value 'legacy' is reserved for ranges mirrored from advisories.below.
  ecosystem      TEXT NOT NULL DEFAULT '',
  -- NULL distro = not distro-specific (upstream or legacy floor).
  -- NULL release with a distro = every release of that distro.
  distro         TEXT,
  release        TEXT,
  -- Binary package name as installed, and the source package it is built from
  -- (Debian/Ubuntu trackers key on the source name).
  package        TEXT NOT NULL CHECK (package <> ''),
  source_package TEXT,
  -- NULL introduced = from the first version. NULL fixed = no fix published.
  introduced     TEXT,
  fixed          TEXT,
  fix_state      TEXT NOT NULL CHECK (fix_state IN
                   ('affected', 'fixed', 'will_not_fix', 'not_affected', 'under_investigation')),
  snapshot_id    BIGINT REFERENCES feed_snapshots(id),
  CHECK (fix_state <> 'fixed' OR fixed IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS advisory_ranges_distro_idx
  ON advisory_ranges (distro, release, source_package);
CREATE INDEX IF NOT EXISTS advisory_ranges_package_idx
  ON advisory_ranges (package);
-- One identical range per advisory; also serves lookups by advisory_id.
CREATE UNIQUE INDEX IF NOT EXISTS advisory_ranges_identity_idx
  ON advisory_ranges (advisory_id, ecosystem, COALESCE(distro, ''), COALESCE(release, ''),
                      package, COALESCE(introduced, ''), COALESCE(fixed, ''));

-- Keep the legacy floor and its range in step. Each legacy (package, below)
-- becomes one distro-less range with fixed = below and fix_state 'fixed'. A
-- trigger rather than a one-off copy, because scripts/ingest-osv.py writes
-- advisories directly and keeps doing so until slice 3 replaces it. Rows with
-- an empty package or floor are not mirrored (no range can be built from them).
CREATE OR REPLACE FUNCTION advisories_sync_legacy_range() RETURNS trigger AS $$
BEGIN
  DELETE FROM advisory_ranges WHERE advisory_id = NEW.id AND ecosystem = 'legacy';
  IF NEW.package <> '' AND NEW.below <> '' THEN
    INSERT INTO advisory_ranges (advisory_id, ecosystem, distro, release, package, fixed, fix_state, snapshot_id)
    VALUES (NEW.id, 'legacy', NULL, NULL, NEW.package, NEW.below, 'fixed', NEW.snapshot_id);
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS advisories_sync_legacy_range ON advisories;
CREATE TRIGGER advisories_sync_legacy_range
  AFTER INSERT OR UPDATE OF package, below ON advisories
  FOR EACH ROW EXECUTE FUNCTION advisories_sync_legacy_range();

-- Backfill advisories that already exist. Idempotent: skips any advisory that
-- already has its legacy range.
INSERT INTO advisory_ranges (advisory_id, ecosystem, distro, release, package, fixed, fix_state, snapshot_id)
SELECT a.id, 'legacy', NULL, NULL, a.package, a.below, 'fixed', a.snapshot_id
FROM advisories a
WHERE a.package <> '' AND a.below <> ''
  AND NOT EXISTS (
    SELECT 1 FROM advisory_ranges r WHERE r.advisory_id = a.id AND r.ecosystem = 'legacy'
  );

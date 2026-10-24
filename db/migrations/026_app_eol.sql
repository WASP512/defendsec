-- Application end-of-life (slice 10).
--
-- Software from a third-party repository (Sury's PHP, PGDG's PostgreSQL,
-- NodeSource's Node.js) is covered by no distribution tracker, so a release
-- whose upstream has stopped issuing security fixes was invisible. The
-- endoflife.date feed supplies the release calendar; findings of kind 'eol'
-- say "this release is past upstream support, and it did not come from the
-- distribution, so nobody is patching it".
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- The release calendar, replaced wholesale by each load of the endoflife feed.
-- Dates are NULL where the feed gives none. snapshot_id says which feed fetch
-- the row came from, the way advisory_ranges does.
CREATE TABLE IF NOT EXISTS eol_releases (
  product       TEXT NOT NULL,
  cycle         TEXT NOT NULL,
  label         TEXT NOT NULL DEFAULT '',
  release_date  DATE,
  eoas_from     DATE,
  eol_from      DATE,
  eoes_from     DATE,
  is_eol        BOOLEAN NOT NULL DEFAULT false,
  is_lts        BOOLEAN NOT NULL DEFAULT false,
  latest        TEXT NOT NULL DEFAULT '',
  link          TEXT NOT NULL DEFAULT '',
  snapshot_id   BIGINT REFERENCES feed_snapshots(id),
  PRIMARY KEY (product, cycle)
);

-- Findings gain a kind and a basis. 'eol' sits in the fix bucket beside
-- 'finding': upgrading is the remedy. basis 'lifecycle' says the finding comes
-- from a release calendar, not from an advisory range. Widen the checks only
-- when they do not already allow the new values, so a restart does not rescan
-- the table. (The constraints were created inline in 021 and widened in 022.)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vuln_findings'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''eol''%'
  ) THEN
    ALTER TABLE vuln_findings DROP CONSTRAINT IF EXISTS vuln_findings_kind_check;
    ALTER TABLE vuln_findings ADD CONSTRAINT vuln_findings_kind_check
      CHECK (kind IN ('finding', 'unfixed', 'informational', 'awaiting_vendor', 'eol'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vuln_findings'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%lifecycle%'
  ) THEN
    ALTER TABLE vuln_findings DROP CONSTRAINT IF EXISTS vuln_findings_basis_check;
    ALTER TABLE vuln_findings ADD CONSTRAINT vuln_findings_basis_check
      CHECK (basis IN ('distro', 'upstream', 'lifecycle'));
  END IF;
END
$$;

-- What an end-of-life finding says beyond the columns it shares with the
-- others. advisory_id is 'EOL:<product>:<cycle>' and family is the product, so
-- one release of one product is one finding per host, however many packages it
-- installs.
--   eol_stage    'eol' (security support ended) or 'eoas' (active support ended)
--   eol_date     the day that stage began
--   origin       the repository or vendor the packages came from, as the agent
--                read it (the apt Origin:, the rpm Vendor), and origin_repo the
--                repository itself
--   eol_detail   JSON: product label, package list, upgrade target, latest
--                release, link, end of extended support
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS eol_product TEXT NOT NULL DEFAULT '';
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS eol_cycle TEXT NOT NULL DEFAULT '';
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS eol_stage TEXT NOT NULL DEFAULT ''
  CHECK (eol_stage IN ('', 'eol', 'eoas'));
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS eol_date DATE;
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT '';
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS origin_repo TEXT NOT NULL DEFAULT '';
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS eol_detail JSONB;

-- What the last match run examined for application end-of-life, so an empty
-- list can be read next to it: of eol_mapped packages the mapping table knows,
-- eol_distro were the distribution's own (not judged) and eol_unknown had no
-- readable origin (not assessed, never "clean").
ALTER TABLE host_vuln_state ADD COLUMN IF NOT EXISTS eol_mapped INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_vuln_state ADD COLUMN IF NOT EXISTS eol_distro INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_vuln_state ADD COLUMN IF NOT EXISTS eol_unknown INTEGER NOT NULL DEFAULT 0;

-- The exposure list's fix bucket reads kind IN ('finding', 'eol').
CREATE INDEX IF NOT EXISTS vuln_findings_open_eol_idx
  ON vuln_findings (advisory_id) WHERE resolved_at IS NULL AND kind = 'eol';

-- Windows edition (EditionID): client, server and LTSC editions share build
-- numbers and have different support dates, so the Supported OS policy needs
-- it. Empty for Linux hosts and for agents that predate the field.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_edition TEXT NOT NULL DEFAULT '';

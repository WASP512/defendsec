-- Repository health (slice 11).
--
-- An expired repository key makes apt keep using the index it downloaded while
-- the key was valid, without failing, so "no pending updates" can be a lie. The
-- agent now reports what it read about each enabled repository (signature
-- state, Release dates, when the host last refreshed), the server judges it,
-- and a repository with a problem becomes a finding of kind 'repo_health'.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- What the agent reported about the host's repositories, with the server's
-- verdict on whether the host's pending-updates list can be believed (the
-- repohealth.Report JSON). NULL for a host whose agent predates the report.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS repo_health JSONB;

-- A repo_health finding sits in the fix bucket beside 'finding' and 'eol': the
-- remedy (install the vendor's current key, refresh the index) is work for this
-- week. basis 'host' says the finding comes from what the host reports about
-- its own configuration. Widen the checks only when they do not already allow
-- the new values, so a restart does not rescan the table.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vuln_findings'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''repo_health''%'
  ) THEN
    ALTER TABLE vuln_findings DROP CONSTRAINT IF EXISTS vuln_findings_kind_check;
    ALTER TABLE vuln_findings ADD CONSTRAINT vuln_findings_kind_check
      CHECK (kind IN ('finding', 'unfixed', 'informational', 'awaiting_vendor', 'eol', 'repo_health'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vuln_findings'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''host''%'
  ) THEN
    ALTER TABLE vuln_findings DROP CONSTRAINT IF EXISTS vuln_findings_basis_check;
    ALTER TABLE vuln_findings ADD CONSTRAINT vuln_findings_basis_check
      CHECK (basis IN ('distro', 'upstream', 'lifecycle', 'host'));
  END IF;
END
$$;

-- What a repository-health finding says beyond the columns it shares with the
-- others. advisory_id is 'REPO:' and twelve hex digits of the repository id, and
-- the family (source_package) is the repository id, so one repository is one
-- finding per host however many problems it has. repo_detail is JSON: the
-- repository's label, address and suite, every problem with its severity and
-- wording, the evidence dates, and the fix text.
ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS repo_detail JSONB;

-- The exposure list's fix bucket reads kind IN ('finding', 'eol', 'repo_health').
CREATE INDEX IF NOT EXISTS vuln_findings_open_repo_idx
  ON vuln_findings (advisory_id) WHERE resolved_at IS NULL AND kind = 'repo_health';

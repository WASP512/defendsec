-- Rebuild distributions and the awaiting_vendor state (slice 4c).
--
-- Rocky Linux and AlmaLinux rebuild Red Hat's packages and publish their own
-- errata afterwards, so Red Hat's feed can say "fixed in 5.14.0-687.60.1" days
-- before a Rocky host can install it. A finding the operator cannot act on must
-- not rank as "fix this week", so findings gain a fourth kind:
--
--   awaiting_vendor   fixed upstream (Red Hat), not yet released by the host's
--                     own distribution. Counted with the no-fix/watch bucket,
--                     never as fixable.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- The date the vendor published the erratum behind a range ("fixed upstream by
-- Red Hat on 2026-10-20"). NULL where the feed does not say.
ALTER TABLE advisory_ranges ADD COLUMN IF NOT EXISTS issued DATE;

-- Widen vuln_findings.kind. The constraint was created inline in 021, so it has
-- the generated name vuln_findings_kind_check; replace it only when it does not
-- already allow the new kind, so a restart does not rescan the table.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'vuln_findings'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%awaiting_vendor%'
  ) THEN
    ALTER TABLE vuln_findings DROP CONSTRAINT IF EXISTS vuln_findings_kind_check;
    ALTER TABLE vuln_findings ADD CONSTRAINT vuln_findings_kind_check
      CHECK (kind IN ('finding', 'unfixed', 'informational', 'awaiting_vendor'));
  END IF;
END
$$;

-- Red Hat ranges loaded before this migration carry no issue date, and a feed
-- whose upstream file has not changed is not re-read, so they would stay
-- dateless until Red Hat next publishes. Forget the loaded digest of the RHEL
-- feeds once, so the next sync re-reads them and fills the dates in. Guarded by
-- a meta flag because this file runs on every start.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM meta WHERE key = 'rhel_issued_reload') THEN
    UPDATE feed_status SET sha256 = '' WHERE kind = 'rhel';
    INSERT INTO meta (key, value) VALUES ('rhel_issued_reload', '1') ON CONFLICT (key) DO NOTHING;
  END IF;
END
$$;

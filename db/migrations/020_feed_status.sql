-- Feed sync state (slice 3).
--
-- defendsec-feeds records, per feed, when it was last confirmed current, what
-- it loaded and the HTTP validators needed for a conditional re-fetch. The
-- admin API (GET /v1/feeds) and the console's feed-age banner read this table.
-- Every statement is idempotent: migration files re-run on every start.

CREATE TABLE IF NOT EXISTS feed_status (
  name            TEXT PRIMARY KEY,
  kind            TEXT NOT NULL DEFAULT '',
  url             TEXT NOT NULL DEFAULT '',
  -- Last time a sync tried this feed, and the error if that attempt failed.
  last_attempt_at TIMESTAMPTZ,
  last_error      TEXT NOT NULL DEFAULT '',
  -- Last time the feed was confirmed current AND loaded. For an air-gapped
  -- import this is the bundle's fetch time, not the import time, so the age
  -- shown is the age of the data.
  last_success_at TIMESTAMPTZ,
  record_count    BIGINT NOT NULL DEFAULT 0 CHECK (record_count >= 0),
  -- SHA-256 of the upstream file whose records are currently loaded.
  sha256          TEXT NOT NULL DEFAULT '',
  etag            TEXT NOT NULL DEFAULT '',
  last_modified   TEXT NOT NULL DEFAULT '',
  snapshot_id     BIGINT REFERENCES feed_snapshots(id)
);

-- EPSS and KEV enrichment join feed rows to advisories by CVE id.
CREATE INDEX IF NOT EXISTS advisories_cve_idx ON advisories (cve) WHERE cve <> '';

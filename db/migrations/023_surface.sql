-- External surface scanner (slice 7a).
--
-- Assets are what the operator declares and confirms as authorised to test; the
-- scanner only ever reads rows with authorised = true and removed_at IS NULL.
-- Findings keep first-seen / resolved bookkeeping exactly like vuln_findings:
-- rows are never deleted when a finding goes away, resolved_at is set, so
-- "open on date A, closed on date B" stays answerable. Observations are the raw
-- record text and certificate fields behind every check of every scan, so a
-- finding can be reproduced later.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

CREATE TABLE IF NOT EXISTS surface_assets (
  id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind           TEXT NOT NULL CHECK (kind IN ('domain', 'hostname', 'ip')),
  value          TEXT NOT NULL,
  label          TEXT NOT NULL DEFAULT '',
  dkim_selectors TEXT[] NOT NULL DEFAULT '{}',
  shared_hosting BOOLEAN NOT NULL DEFAULT false,
  mail_host      BOOLEAN NOT NULL DEFAULT false,
  -- The "I am authorised to test this asset" confirmation, with who gave it and
  -- when. Revoking it stops scanning at once.
  authorised     BOOLEAN NOT NULL DEFAULT false,
  authorised_by  TEXT NOT NULL DEFAULT '',
  authorised_at  TIMESTAMPTZ,
  created_by     TEXT NOT NULL DEFAULT '',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_scan_at   TIMESTAMPTZ,
  -- Removing an asset hides it and stops scanning but keeps its findings and
  -- observations as evidence. Declaring it again reactivates the row.
  removed_at     TIMESTAMPTZ,
  UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS surface_scans (
  id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id            BIGINT NOT NULL REFERENCES surface_assets(id) ON DELETE CASCADE,
  triggered_by        TEXT NOT NULL CHECK (triggered_by IN ('manual', 'schedule')),
  started_at          TIMESTAMPTZ NOT NULL,
  finished_at         TIMESTAMPTZ NOT NULL,
  checks_assessed     INTEGER NOT NULL DEFAULT 0,
  checks_not_assessed INTEGER NOT NULL DEFAULT 0,
  findings_open       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS surface_scans_asset_idx ON surface_scans (asset_id, started_at DESC);

-- One row per check group per scan. assessed = false means the check could not
-- run or reach a conclusion (reason says why): missing evidence, not a pass.
CREATE TABLE IF NOT EXISTS surface_observations (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id     BIGINT NOT NULL REFERENCES surface_scans(id) ON DELETE CASCADE,
  asset_id    BIGINT NOT NULL REFERENCES surface_assets(id) ON DELETE CASCADE,
  check_group TEXT NOT NULL,
  assessed    BOOLEAN NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  observed    JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS surface_observations_latest_idx
  ON surface_observations (asset_id, check_group, observed_at DESC);

-- (asset_id, finding_id, subject) is a finding's identity on an asset:
-- finding_id names the condition ("dmarc.p_none"), subject tells apart several
-- of one condition (a DKIM selector, a port, an MX host).
CREATE TABLE IF NOT EXISTS surface_findings (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  asset_id      BIGINT NOT NULL REFERENCES surface_assets(id) ON DELETE CASCADE,
  check_group   TEXT NOT NULL,
  finding_id    TEXT NOT NULL,
  subject       TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title         TEXT NOT NULL,
  detail        TEXT NOT NULL DEFAULT '',
  fix           TEXT NOT NULL DEFAULT '',
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  controls      TEXT[] NOT NULL DEFAULT '{}',
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at   TIMESTAMPTZ,
  first_scan_id BIGINT REFERENCES surface_scans(id) ON DELETE SET NULL,
  last_scan_id  BIGINT REFERENCES surface_scans(id) ON DELETE SET NULL,
  UNIQUE (asset_id, finding_id, subject)
);

CREATE INDEX IF NOT EXISTS surface_findings_open_idx
  ON surface_findings (asset_id) WHERE resolved_at IS NULL;

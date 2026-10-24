-- Identity posture (slice 12: Microsoft 365; slice 13 adds Google Workspace to the
-- same tables). What a client's tenant says about how its accounts could be taken
-- over and how mail could be hidden or redirected, read through the provider's
-- read-only API with nothing installed.
--
-- identity_findings keeps first-seen / resolved bookkeeping exactly like
-- surface_findings and vuln_findings: rows are never deleted when a finding goes
-- away, resolved_at is set, so "open on date A, closed on date B" stays
-- answerable. A run records, per check group, whether it was assessed: a check
-- that could not run resolves nothing and produces nothing (missing evidence is
-- not a pass).
--
-- Evidence is a rule's name, conditions and actions, registration flags, policy
-- names and states. Never message content: nothing here has a column for it.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- One tenant per instance. The tenant and application IDs are identifiers, not
-- secrets; the certificate or client secret is never here, it comes from a file
-- named in apid's environment.
CREATE TABLE IF NOT EXISTS m365_settings (
  id                INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  tenant_id         TEXT NOT NULL DEFAULT '',
  client_id         TEXT NOT NULL DEFAULT '',
  cloud             TEXT NOT NULL DEFAULT 'global' CHECK (cloud IN ('global', 'usgov', 'china')),
  -- More Global Administrators than this is a finding.
  global_admin_max  INT NOT NULL DEFAULT 4 CHECK (global_admin_max BETWEEN 1 AND 50),
  -- Domains, besides the tenant's own, a rule may forward to without being "outside".
  trusted_domains   TEXT[] NOT NULL DEFAULT '{}',
  -- Added to the built-in finance words (invoice, payment, QuickBooks, ...).
  finance_terms     TEXT[] NOT NULL DEFAULT '{}',
  -- Name the destination folder of move rules. Needs the optional Mail.ReadBasic.All.
  resolve_folders   BOOLEAN NOT NULL DEFAULT false,
  updated_by        TEXT NOT NULL DEFAULT '',
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per read of a tenant. status:
--   ok            every check ran on every mailbox
--   partial       some check or mailbox could not be read (reason says which)
--   not_assessed  nothing could be read (credentials refused, no permission)
-- checks is [{check, assessed, reason, observed}] for each check group;
-- not_assessed is the list of what the provider's API cannot show.
CREATE TABLE IF NOT EXISTS identity_runs (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  provider      TEXT NOT NULL,
  tenant        TEXT NOT NULL DEFAULT '',
  triggered_by  TEXT NOT NULL DEFAULT 'schedule',
  started_at    TIMESTAMPTZ NOT NULL,
  finished_at   TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'not_assessed')),
  reason        TEXT NOT NULL DEFAULT '',
  requests      INT NOT NULL DEFAULT 0,
  counts        JSONB NOT NULL DEFAULT '{}'::jsonb,
  checks        JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(checks) = 'array'),
  not_assessed  JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(not_assessed) = 'array'),
  findings_open INT NOT NULL DEFAULT 0,
  opened        INT NOT NULL DEFAULT 0,
  resolved      INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS identity_runs_finished_idx ON identity_runs (provider, finished_at DESC);

-- (provider, finding_id, subject) is a finding's identity: finding_id names the
-- condition ("mfa.not_registered"), subject tells apart several of one (a user's
-- object id; "<user id>/<rule id>" for an inbox rule; "tenant").
CREATE TABLE IF NOT EXISTS identity_findings (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  provider      TEXT NOT NULL,
  check_group   TEXT NOT NULL,
  finding_id    TEXT NOT NULL,
  subject       TEXT NOT NULL,
  subject_label TEXT NOT NULL DEFAULT '',
  severity      TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  title         TEXT NOT NULL,
  detail        TEXT NOT NULL DEFAULT '',
  fix           TEXT NOT NULL DEFAULT '',
  evidence      JSONB NOT NULL DEFAULT '{}'::jsonb,
  controls      TEXT[] NOT NULL DEFAULT '{}',
  first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at   TIMESTAMPTZ,
  first_run_id  BIGINT REFERENCES identity_runs(id) ON DELETE SET NULL,
  last_run_id   BIGINT REFERENCES identity_runs(id) ON DELETE SET NULL,
  UNIQUE (provider, finding_id, subject)
);
CREATE INDEX IF NOT EXISTS identity_findings_open_idx ON identity_findings (provider) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS identity_findings_span_idx ON identity_findings (first_seen, resolved_at);

-- The interval that ended when a closed finding came back, copied before
-- first_seen restarts, so the days it was closed never count as open and the
-- trendline survives a recurrence (as surface_finding_intervals does).
CREATE TABLE IF NOT EXISTS identity_finding_intervals (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  provider   TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  subject    TEXT NOT NULL,
  severity   TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  opened_at  TIMESTAMPTZ NOT NULL,
  closed_at  TIMESTAMPTZ NOT NULL,
  UNIQUE (provider, finding_id, subject, opened_at)
);
CREATE INDEX IF NOT EXISTS identity_finding_intervals_window_idx ON identity_finding_intervals (opened_at, closed_at);

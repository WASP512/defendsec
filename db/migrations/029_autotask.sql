-- Autotask tickets from Fix this week (slice 14).
--
-- One DefendSec instance maps to one Autotask company. Three tables:
--
--   autotask_settings  the one company and how its tickets look. Every picklist
--                      value is an Autotask picklist value (a number as text)
--                      the operator chose from the live list; nothing here is a
--                      default of ours except dry run, no auto-complete and "high
--                      and up". No credential: the API user's secret and the
--                      integration code are files named in apid's environment.
--   autotask_tickets   the idempotency record: one row per remediation action and
--                      generation, with the Autotask ticket id and the tag that is
--                      also in the ticket's title. A re-run reads this first; if a
--                      row is lost the ticket is found again by its tag.
--   autotask_runs      every run, dry or live, with the exact operations it showed
--                      or did. A live run needs a dry run with the same settings
--                      fingerprint behind it.
--
-- Every ticket action (created, adopted, note added, completed, state change) is
-- also an audit_log entry written in the same transaction as the row it changes.
--
-- Every statement is idempotent: migration files re-run on every start.

CREATE TABLE IF NOT EXISTS autotask_settings (
  id                INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  mode              TEXT NOT NULL DEFAULT 'dry_run' CHECK (mode IN ('dry_run', 'live')),
  api_user          TEXT NOT NULL DEFAULT '',
  zone_url          TEXT NOT NULL DEFAULT '',
  company_id        BIGINT NOT NULL DEFAULT 0 CHECK (company_id >= 0),
  queue_id          TEXT NOT NULL DEFAULT '',
  status            TEXT NOT NULL DEFAULT '',
  source            TEXT NOT NULL DEFAULT '',
  issue_type        TEXT NOT NULL DEFAULT '',
  sub_issue_type    TEXT NOT NULL DEFAULT '',
  priority_critical TEXT NOT NULL DEFAULT '',
  priority_high     TEXT NOT NULL DEFAULT '',
  priority_medium   TEXT NOT NULL DEFAULT '',
  note_type         TEXT NOT NULL DEFAULT '',
  note_publish      TEXT NOT NULL DEFAULT '',
  auto_complete     BOOLEAN NOT NULL DEFAULT false,
  complete_status   TEXT NOT NULL DEFAULT '',
  min_urgency       TEXT NOT NULL DEFAULT 'high' CHECK (min_urgency IN ('critical', 'high', 'medium')),
  due_days_critical INT NOT NULL DEFAULT 2 CHECK (due_days_critical BETWEEN 1 AND 90),
  due_days_high     INT NOT NULL DEFAULT 7 CHECK (due_days_high BETWEEN 1 AND 90),
  due_days_medium   INT NOT NULL DEFAULT 14 CHECK (due_days_medium BETWEEN 1 AND 90),
  console_url       TEXT NOT NULL DEFAULT '',
  max_creates       INT NOT NULL DEFAULT 10 CHECK (max_creates BETWEEN 1 AND 50),
  updated_by        TEXT NOT NULL DEFAULT '',
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS autotask_tickets (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  group_key     TEXT NOT NULL,
  generation    INT NOT NULL DEFAULT 1 CHECK (generation >= 1),
  tag           TEXT NOT NULL UNIQUE,
  ticket_id     BIGINT NOT NULL,
  ticket_number TEXT NOT NULL DEFAULT '',
  company_id    BIGINT NOT NULL,
  title         TEXT NOT NULL DEFAULT '',
  state         TEXT NOT NULL CHECK (state IN ('open', 'resolved', 'closed_in_psa')),
  urgency       TEXT NOT NULL CHECK (urgency IN ('critical', 'high', 'medium', 'low')),
  -- Member key -> {label, digest}: what the ticket has been told about.
  members       JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(members) = 'object'),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at   TIMESTAMPTZ,
  UNIQUE (group_key, generation)
);
CREATE INDEX IF NOT EXISTS autotask_tickets_state_idx ON autotask_tickets (state);

CREATE TABLE IF NOT EXISTS autotask_runs (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  mode            TEXT NOT NULL CHECK (mode IN ('dry_run', 'live')),
  triggered_by    TEXT NOT NULL DEFAULT 'schedule',
  started_at      TIMESTAMPTZ NOT NULL,
  finished_at     TIMESTAMPTZ NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'not_run')),
  verified        BOOLEAN NOT NULL DEFAULT false,
  unverified_why  TEXT NOT NULL DEFAULT '',
  fingerprint     TEXT NOT NULL DEFAULT '',
  company_name    TEXT NOT NULL DEFAULT '',
  requests        INT NOT NULL DEFAULT 0,
  groups          INT NOT NULL DEFAULT 0,
  below_threshold INT NOT NULL DEFAULT 0,
  created         INT NOT NULL DEFAULT 0,
  noted           INT NOT NULL DEFAULT 0,
  completed       INT NOT NULL DEFAULT 0,
  failed          INT NOT NULL DEFAULT 0,
  deferred        INT NOT NULL DEFAULT 0,
  flagged         INT NOT NULL DEFAULT 0,
  problems        JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(problems) = 'array'),
  ops             JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(ops) = 'array')
);
CREATE INDEX IF NOT EXISTS autotask_runs_finished_idx ON autotask_runs (finished_at DESC);

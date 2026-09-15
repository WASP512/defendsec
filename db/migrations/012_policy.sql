-- Phase 2: policy-governed response.
--
-- Authorisation was binary: an admin token could issue any command to any
-- host. That is sufficient for a homelab and insufficient for anything else,
-- and it is the blocker for safe automation.

-- Host classes drive policy: production, critical, domain-controller.
-- Stored on the device rather than in the policy file so a rule reads
-- "hosts classed production" and stays correct as the estate changes.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS classes TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS devices_classes_idx ON devices USING GIN (classes);

-- Every policy decision, permit and deny alike.
--
-- Denials are evidence. A tool that records only what it did, and not what it
-- refused, cannot answer "did anyone try" — which is the question asked after
-- an incident, and the one a deny-by-default engine is uniquely able to answer.
CREATE TABLE IF NOT EXISTS policy_decisions (
  id             TEXT PRIMARY KEY,
  at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor          TEXT        NOT NULL DEFAULT '',
  role           TEXT        NOT NULL DEFAULT '',
  command_type   TEXT        NOT NULL,
  device_id      TEXT        NOT NULL DEFAULT '',
  hostname       TEXT        NOT NULL DEFAULT '',
  host_classes   TEXT[]      NOT NULL DEFAULT '{}',
  effect         TEXT        NOT NULL,
  rule_id        TEXT        NOT NULL DEFAULT '',
  reason         TEXT        NOT NULL DEFAULT '',
  -- Which policy text decided. Recorded per decision so the question "what
  -- did the policy say at the time" is answerable from the ledger rather than
  -- from whatever is on disk today.
  policy_name    TEXT        NOT NULL DEFAULT '',
  policy_hash    TEXT        NOT NULL DEFAULT '',
  limit_exceeded TEXT        NOT NULL DEFAULT '',
  break_glass_id TEXT        NOT NULL DEFAULT '',
  -- The command this decision produced, when it permitted one.
  command_id     TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS policy_decisions_at_idx      ON policy_decisions (at DESC);
CREATE INDEX IF NOT EXISTS policy_decisions_effect_idx  ON policy_decisions (effect);
CREATE INDEX IF NOT EXISTS policy_decisions_device_idx  ON policy_decisions (device_id);
CREATE INDEX IF NOT EXISTS policy_decisions_command_idx ON policy_decisions (command_id) WHERE command_id <> '';

-- Commands awaiting a second approver (roadmap 2.3).
--
-- A pending command is deliberately NOT a signed command with a flag. It has
-- no signature at all until the approvals are in, so an attacker who flips a
-- boolean in the database still has nothing an agent will execute.
CREATE TABLE IF NOT EXISTS pending_commands (
  id                 TEXT PRIMARY KEY,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  device_id          TEXT        NOT NULL,
  hostname           TEXT        NOT NULL DEFAULT '',
  command_type       TEXT        NOT NULL,
  payload            TEXT        NOT NULL DEFAULT '{}',
  requested_by       TEXT        NOT NULL,
  required_approvals INT         NOT NULL,
  rule_id            TEXT        NOT NULL DEFAULT '',
  policy_hash        TEXT        NOT NULL DEFAULT '',
  status             TEXT        NOT NULL DEFAULT 'pending',
  -- Set once the command is signed and issued.
  command_id         TEXT        NOT NULL DEFAULT '',
  CONSTRAINT pending_commands_expiry CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS pending_commands_status_idx ON pending_commands (status, expires_at);

-- Approvals are rows, not a counter. A counter can be incremented; rows name
-- who approved, and the unique constraint is what stops one person approving
-- twice to satisfy a two-person rule.
CREATE TABLE IF NOT EXISTS pending_command_approvals (
  pending_id TEXT        NOT NULL REFERENCES pending_commands(id) ON DELETE CASCADE,
  actor      TEXT        NOT NULL,
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (pending_id, actor)
);

-- Break-glass bypasses (roadmap 2.4).
CREATE TABLE IF NOT EXISTS break_glass (
  id            TEXT PRIMARY KEY,
  justification TEXT        NOT NULL,
  opened_by     TEXT        NOT NULL,
  opened_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- An emergency bypass with no expiry is a permanent one.
  expires_at    TIMESTAMPTZ NOT NULL,
  closed_at     TIMESTAMPTZ,
  closed_by     TEXT        NOT NULL DEFAULT '',
  CONSTRAINT break_glass_expiry CHECK (expires_at > opened_at)
);

CREATE INDEX IF NOT EXISTS break_glass_open_idx ON break_glass (expires_at DESC) WHERE closed_at IS NULL;

-- Phase 4: the AI control plane.
--
-- An AI agent is a principal, and deliberately not a user.
--
-- The alternative was a third role on the users table. That would have been
-- less code and a worse design: a role is a string compared at each call
-- site, and the guarantee this phase sells — that an agent cannot sign its
-- own authority — would then rest on every one of those comparisons being
-- written correctly, forever. Agents live in their own table instead, and the
-- admin API resolves callers only against users and sessions. An agent token
-- presented to the command endpoint is not an under-privileged caller; it is
-- not a caller the admin API can see at all.

CREATE TABLE IF NOT EXISTS agent_principals (
  id           TEXT PRIMARY KEY,
  -- name is how the agent appears in the ledger, as "agent:<name>".
  name         TEXT        NOT NULL UNIQUE,
  -- token_hash is SHA-256 of the bearer token. The token itself is shown once
  -- at creation and never stored, so a database copy does not yield a working
  -- credential.
  token_hash   TEXT        NOT NULL UNIQUE,
  -- model is the model identity the operator says is behind this principal,
  -- recorded so an auditor can ask what recommended an action and not only
  -- who approved it. Self-reported: DefendSec cannot verify which model is on
  -- the other end of a token, and the audit record says so rather than
  -- implying an attestation it does not have.
  model        TEXT        NOT NULL DEFAULT '',
  description  TEXT        NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   TEXT        NOT NULL DEFAULT '',
  disabled     BOOLEAN     NOT NULL DEFAULT false,
  last_seen_at TIMESTAMPTZ,
  -- revoked_at makes a withdrawal permanent and auditable. Trivially
  -- revocable is part of the Phase 4 claim, and a deleted row would leave no
  -- evidence the principal ever existed.
  revoked_at   TIMESTAMPTZ,
  revoked_by   TEXT        NOT NULL DEFAULT ''
);

-- Proposal provenance on a pending command.
--
-- A proposal is stored in pending_commands like any other request awaiting
-- approval, which is the point: an AI proposal and an unsigned human request
-- are structurally the same object, and neither carries a signature. What
-- these columns add is the part an auditor needs that a human request does
-- not have — what recommended this, on what evidence, and under what prompt.
ALTER TABLE pending_commands
  ADD COLUMN IF NOT EXISTS proposed_by_agent TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS proposal_model    TEXT NOT NULL DEFAULT '',
  -- The model's stated reasoning, verbatim. Stored as given and never
  -- interpreted: it is evidence about what the model said, not an input to
  -- any decision DefendSec makes.
  ADD COLUMN IF NOT EXISTS proposal_reasoning TEXT NOT NULL DEFAULT '',
  -- The DefendSec records the model says it relied on — alert ids, advisory
  -- ids, host ids. An auditor reconstructing the decision needs the evidence
  -- the recommendation rested on, not only the recommendation.
  ADD COLUMN IF NOT EXISTS proposal_evidence TEXT[] NOT NULL DEFAULT '{}',
  -- Prompt provenance: what the agent says it was asked to do. Untrusted and
  -- unparsed, recorded so the question "who set this agent on this task" has
  -- an answer in the ledger.
  ADD COLUMN IF NOT EXISTS proposal_prompt   TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS pending_commands_proposed_by_agent_idx
  ON pending_commands (proposed_by_agent)
  WHERE proposed_by_agent <> '';

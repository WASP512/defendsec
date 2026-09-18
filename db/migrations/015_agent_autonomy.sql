-- Phase 4.4: bounded autonomy.
--
-- Autonomy needs two independent switches, and this is the second.
--
-- The first is in the policy document: a rule marked `autonomous: true`. That
-- is the operator declaring which narrow capability may run unattended, and it
-- is validated at load time — it must permit rather than deny, must not also
-- demand approvals, and must have a blast-radius limit covering every command
-- it names.
--
-- The second is here, per principal. Without it, withdrawing autonomy from one
-- misbehaving agent would mean editing and reloading the policy file, which
-- also withdraws it from every other agent and takes a config change to undo.
-- "Trivially revocable" has to mean one call against one principal, and it
-- cannot require touching the document that governs everyone.
--
-- Both must be true. Either one being false means the proposal goes to a human
-- exactly as it did before, which is the behaviour the default preserves:
-- false here, absent there.
ALTER TABLE agent_principals
  ADD COLUMN IF NOT EXISTS autonomy_enabled BOOLEAN NOT NULL DEFAULT false,
  -- Who granted it and when. An autonomous agent is the most consequential
  -- thing an operator can configure here, so the grant is itself evidence
  -- rather than a bare boolean somebody may or may not remember setting.
  ADD COLUMN IF NOT EXISTS autonomy_granted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS autonomy_granted_by TEXT NOT NULL DEFAULT '';

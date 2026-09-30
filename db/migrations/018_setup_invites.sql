-- First-admin invites (login follow-up to 5.4).
--
-- `defendsec-apid bootstrap-admin`, run on the server, prints a one-time URL
-- that lets its holder create the first administrator. Running a command on
-- the server is the proof of ownership; the setup window after start is the
-- other. Only the hash is stored, invites expire, and one use consumes it.
CREATE TABLE IF NOT EXISTS setup_invites (
  token_hash  TEXT PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

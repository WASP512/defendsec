-- Phase 1.0: real accounts, so the ledger can name a person.
--
-- Every console session shared one bearer token, so commands and audit entries
-- recorded actor_identity as 'shared-admin-token' — a role, not a person. No
-- amount of signing makes that non-repudiable: the signature proves the server
-- authorised an action, never who asked for it. Under CJIS a shared token with
-- no second factor is also a direct policy violation.

CREATE TABLE IF NOT EXISTS users (
  id             TEXT PRIMARY KEY,
  username       TEXT NOT NULL,
  display_name   TEXT NOT NULL DEFAULT '',
  role           TEXT NOT NULL,
  password_hash  TEXT NOT NULL,
  disabled       BOOLEAN NOT NULL DEFAULT FALSE,

  -- Second factor. totp_last_counter is what makes a code single-use: a
  -- code at or below it is refused, so an observed code cannot be replayed
  -- for the rest of its window.
  totp_secret       TEXT   NOT NULL DEFAULT '',
  totp_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
  totp_last_counter BIGINT NOT NULL DEFAULT 0,

  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  last_login_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Usernames are unique case-insensitively, so a differently-cased twin cannot
-- shadow an account or make two ledger actors look like one person.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users (lower(username));

-- Sessions store only the SHA-256 of the token. A read of this table then
-- yields nothing usable, which matters because the threat model this phase is
-- built around includes someone holding database access.
CREATE TABLE IF NOT EXISTS user_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  -- False for a session created from the bootstrap shared token rather than a
  -- named account. Those actions cannot be traced to a person and the ledger
  -- says so rather than implying an attribution it does not have.
  attributed BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS user_sessions_expires_idx ON user_sessions (expires_at);

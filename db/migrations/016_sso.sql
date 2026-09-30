-- Phase 5.4: single sign-on (OIDC).
--
-- An SSO account is linked by (issuer, subject), never by username. The
-- identity provider's `sub` claim is the only identifier it promises is
-- stable and unique; usernames and email addresses can be reassigned, and
-- matching on them would let whoever holds a name at the IdP take over the
-- local account that happens to share it.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS sso_issuer  TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS sso_subject TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS users_sso_identity_idx
  ON users (sso_issuer, sso_subject)
  WHERE sso_subject <> '';

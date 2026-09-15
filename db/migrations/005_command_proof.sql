-- Phase 1.1: keep the proof, not just the fact.
--
-- Commands were already Ed25519-signed in transit and the signature was then
-- discarded, so the stored record asserted what happened without being able to
-- prove it. These columns retain the signature and the envelope fields it
-- covers.
--
-- The canonical bytes are not stored: they are rebuilt deterministically from
-- (device_id, id, type, issued_unix, expires_unix, payload), all of which are
-- columns here, which keeps the row self-verifying without duplicating data.

ALTER TABLE commands ADD COLUMN IF NOT EXISTS signature      TEXT   NOT NULL DEFAULT '';
ALTER TABLE commands ADD COLUMN IF NOT EXISTS signing_key_id TEXT   NOT NULL DEFAULT '';
ALTER TABLE commands ADD COLUMN IF NOT EXISTS issued_unix    BIGINT NOT NULL DEFAULT 0;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS expires_unix   BIGINT NOT NULL DEFAULT 0;

-- Who authorised it. Defaults to the shared-token actor until per-user
-- identity lands (roadmap 1.0); rows written under the shared token cannot be
-- attributed to an individual and should not be presented as if they can.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS actor_identity TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS commands_signing_key_idx ON commands (signing_key_id);

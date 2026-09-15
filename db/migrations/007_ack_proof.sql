-- Phase 1.3: make the endpoint's claim of execution provable too.
--
-- A command already carries the server's proof that it was authorised. The
-- acknowledgement coming back carried none: it was authenticated only by the
-- mTLS channel, so once the record was stored there was nothing to separate
-- "we sent this" from "this ran". These columns retain the agent's signature
-- over the result.
--
-- Agents sign with the ECDSA P-256 key from their enrolled certificate, which
-- is already the identity mTLS authenticates and the one revocation targets,
-- so the public half is recorded on the device at enrollment.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_public_key_pem TEXT NOT NULL DEFAULT '';

ALTER TABLE commands ADD COLUMN IF NOT EXISTS ack_signature    TEXT   NOT NULL DEFAULT '';
ALTER TABLE commands ADD COLUMN IF NOT EXISTS ack_result_hash  TEXT   NOT NULL DEFAULT '';
ALTER TABLE commands ADD COLUMN IF NOT EXISTS ack_executed_unix BIGINT NOT NULL DEFAULT 0;

-- Whether the server could check the signature when the acknowledgement
-- arrived. Agents predating this migration send none, and those rows are
-- recorded as unattested rather than rejected, so an upgrade does not silently
-- drop endpoints.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS ack_verified BOOLEAN NOT NULL DEFAULT FALSE;

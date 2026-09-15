-- Phase 1.6: transparency anchoring.
--
-- The hash chain defeats an attacker who can edit the database. Signed
-- checkpoints defeat one who can append. Neither defeats an attacker who owns
-- the server, the database *and* the control signing key: that attacker can
-- rebuild the whole chain and sign a fresh checkpoint over it, and the result
-- is internally perfect.
--
-- An anchor is a copy of a checkpoint hash published where that attacker
-- cannot reach back and alter it. They can stop new anchors appearing; they
-- cannot rewrite the ones already out there, so a rebuilt chain stops matching
-- and the forgery becomes visible.

CREATE TABLE IF NOT EXISTS audit_anchors (
  id            TEXT PRIMARY KEY,
  through_seq   BIGINT      NOT NULL,
  entry_hash    TEXT        NOT NULL,
  kind          TEXT        NOT NULL,
  target        TEXT        NOT NULL DEFAULT '',
  anchored_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- What the third party says, where it says anything: an RFC 3161 genTime,
  -- a peer's receive time. Null for a file target, which has no clock of
  -- its own.
  external_time TIMESTAMPTZ,
  -- Whatever the target returned, stored verbatim so it can be checked by
  -- tooling that is not DefendSec. A timestamp token is verified with
  -- `openssl ts -verify` by someone who trusts a TSA root; DefendSec checks
  -- the imprint and the nonce and does not claim to have checked the rest.
  proof         BYTEA,
  reference     TEXT        NOT NULL DEFAULT '',
  -- Failures are recorded, not discarded. A run of them is the interesting
  -- signal, and an anchor history with failures dropped looks healthier than
  -- it is.
  error         TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_anchors_seq_idx  ON audit_anchors (through_seq DESC);
CREATE INDEX IF NOT EXISTS audit_anchors_kind_idx ON audit_anchors (kind);

-- Anchors received from a peer instance. Kept apart from this instance's own
-- anchors on purpose: they are somebody else's evidence held for them, and
-- mixing the two would let a compromised peer's claims be read as ours.
CREATE TABLE IF NOT EXISTS peer_anchors (
  id             TEXT PRIMARY KEY,
  peer           TEXT        NOT NULL DEFAULT '',
  through_seq    BIGINT      NOT NULL,
  entry_hash     TEXT        NOT NULL,
  signing_key_id TEXT        NOT NULL DEFAULT '',
  signature      TEXT        NOT NULL DEFAULT '',
  checkpoint_at  TIMESTAMPTZ,
  received_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS peer_anchors_peer_idx ON peer_anchors (peer, through_seq DESC);

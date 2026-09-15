-- Phase 1.9: the audit layer.
--
-- Compliance evidence is about a window, not an instant. An assessor does not
-- ask "is this control satisfied right now" — they ask whether it held
-- continuously across the period under review, and what the exceptions were.
-- Everything here exists to make that sentence answerable from stored records
-- rather than reconstructed from memory.

-- An audit period is the window under review: a CJIS triennial, a CMMC
-- assessment year, an internal quarter.
CREATE TABLE IF NOT EXISTS audit_periods (
  id          TEXT PRIMARY KEY,
  name        TEXT        NOT NULL,
  framework   TEXT        NOT NULL,
  starts_at   TIMESTAMPTZ NOT NULL,
  ends_at     TIMESTAMPTZ NOT NULL,
  notes       TEXT        NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by  TEXT        NOT NULL DEFAULT '',
  -- A closed period is a statement that the window is final. Reopening is
  -- possible, but it is an action rather than an oversight, and the ledger
  -- records both.
  closed_at   TIMESTAMPTZ,
  closed_by   TEXT        NOT NULL DEFAULT '',
  CONSTRAINT audit_periods_window CHECK (ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS audit_periods_window_idx ON audit_periods (starts_at, ends_at);

-- A documented exception is the honest half of a compliance view: the control
-- did not hold, somebody decided that was acceptable, and here is who, when
-- and why. Without this, a deficiency has nowhere to go but a spreadsheet, and
-- the assessor is told about it verbally.
--
-- This is deliberately not a POA&M product. It records the exception and its
-- remediation plan; it does not attempt workflow, approval routing or risk
-- scoring, which is where this would stop being a security product (§3.9).
CREATE TABLE IF NOT EXISTS control_exceptions (
  id             TEXT PRIMARY KEY,
  control_id     TEXT        NOT NULL,
  period_id      TEXT        REFERENCES audit_periods(id) ON DELETE SET NULL,
  reason         TEXT        NOT NULL,
  remediation    TEXT        NOT NULL DEFAULT '',
  owner          TEXT        NOT NULL DEFAULT '',
  opened_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  opened_by      TEXT        NOT NULL DEFAULT '',
  -- An exception with no expiry is a permanent excuse. One is required.
  expires_at     TIMESTAMPTZ NOT NULL,
  closed_at      TIMESTAMPTZ,
  closed_by      TEXT        NOT NULL DEFAULT '',
  CONSTRAINT control_exceptions_expiry CHECK (expires_at > opened_at)
);

CREATE INDEX IF NOT EXISTS control_exceptions_control_idx ON control_exceptions (control_id);
CREATE INDEX IF NOT EXISTS control_exceptions_period_idx  ON control_exceptions (period_id);
CREATE INDEX IF NOT EXISTS control_exceptions_open_idx    ON control_exceptions (closed_at) WHERE closed_at IS NULL;

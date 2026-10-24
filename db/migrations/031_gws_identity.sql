-- Google Workspace identity posture (slice 13). It uses the identity_runs,
-- identity_findings and identity_finding_intervals tables of migration 028, with
-- provider = 'google'; the only new thing is how a client's domain is read.
--
-- One domain per instance. Only settings live here: the administrator to act as,
-- how strict the checks are, and which Gmail scope the operator delegated. The
-- service account's key is a file named in apid's environment
-- (DEFENDSEC_GWS_KEY_FILE), never a column, and its identifiers are not stored.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).
CREATE TABLE IF NOT EXISTS gws_settings (
  id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  -- The user the Directory API is read as: a super administrator (a delegated
  -- administrator limited to some organisational units sees only those users).
  admin_email     TEXT NOT NULL DEFAULT '',
  -- readonly: gmail.readonly, the only read-only scope the settings reads accept.
  -- settings.basic: gmail.settings.basic, which cannot read a message but is a write
  -- scope for Gmail settings. Whichever is chosen is what must be delegated.
  gmail_scope     TEXT NOT NULL DEFAULT 'readonly' CHECK (gmail_scope IN ('readonly', 'settings.basic')),
  -- More super administrators than this is a finding.
  super_admin_max INT NOT NULL DEFAULT 4 CHECK (super_admin_max BETWEEN 1 AND 50),
  -- Domains, besides the domain's own, a filter may forward to without being "outside".
  trusted_domains TEXT[] NOT NULL DEFAULT '{}',
  -- Added to the built-in finance words (invoice, payment, QuickBooks, ...).
  finance_terms   TEXT[] NOT NULL DEFAULT '{}',
  updated_by      TEXT NOT NULL DEFAULT '',
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

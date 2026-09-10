-- DefendSec Phase 4+ schema
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enroll_config (
  id            INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enroll_secret TEXT NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id                TEXT PRIMARY KEY,
  hostname          TEXT NOT NULL,
  platform          TEXT NOT NULL DEFAULT 'unknown',
  os_name           TEXT NOT NULL DEFAULT '',
  os_version        TEXT NOT NULL DEFAULT '',
  arch              TEXT NOT NULL DEFAULT '',
  serial            TEXT NOT NULL DEFAULT '',
  hardware_model    TEXT NOT NULL DEFAULT '',
  cpu               TEXT NOT NULL DEFAULT '',
  memory_mb         BIGINT NOT NULL DEFAULT 0,
  disk_encryption   BOOLEAN,
  firewall          BOOLEAN,
  ip_addresses      JSONB NOT NULL DEFAULT '[]',
  username          TEXT NOT NULL DEFAULT '',
  uptime_seconds    BIGINT NOT NULL DEFAULT 0,
  software          JSONB NOT NULL DEFAULT '[]',
  pending_updates   JSONB NOT NULL DEFAULT '[]',
  patch_inventory   TEXT,
  fim               JSONB NOT NULL DEFAULT '[]',
  fim_baseline      JSONB NOT NULL DEFAULT '[]',
  sample            BOOLEAN NOT NULL DEFAULT FALSE,
  enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
  node_key          TEXT NOT NULL DEFAULT '',
  connected         BOOLEAN NOT NULL DEFAULT FALSE,
  isolated          BOOLEAN NOT NULL DEFAULT FALSE,
  cert_fingerprint  TEXT NOT NULL DEFAULT '',
  transport         TEXT NOT NULL DEFAULT 'http',
  agent_version     TEXT NOT NULL DEFAULT '',
  revoked           BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS devices_hostname_idx ON devices (lower(hostname));
CREATE INDEX IF NOT EXISTS devices_last_seen_idx ON devices (last_seen DESC);

CREATE TABLE IF NOT EXISTS fim_events (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  hostname    TEXT NOT NULL,
  path        TEXT NOT NULL,
  previous    TEXT NOT NULL,
  current     TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sample      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS fim_events_detected_idx ON fim_events (detected_at DESC);

CREATE TABLE IF NOT EXISTS triages (
  key        TEXT PRIMARY KEY,
  status     TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS commands (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  hostname    TEXT NOT NULL DEFAULT '',
  type        TEXT NOT NULL,
  payload     TEXT NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL,
  accepted    BOOLEAN NOT NULL DEFAULT FALSE,
  message     TEXT NOT NULL DEFAULT '',
  actor       TEXT NOT NULL DEFAULT 'admin',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS commands_device_idx ON commands (device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id         BIGSERIAL PRIMARY KEY,
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  device_id  TEXT NOT NULL DEFAULT '',
  detail     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS audit_log_at_idx ON audit_log (at DESC);

CREATE TABLE IF NOT EXISTS revoked_certs (
  fingerprint TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  revoked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS advisories (
  id         TEXT PRIMARY KEY,
  cve        TEXT NOT NULL DEFAULT '',
  package    TEXT NOT NULL,
  below      TEXT NOT NULL,
  severity   TEXT NOT NULL,
  summary    TEXT NOT NULL DEFAULT '',
  source     TEXT NOT NULL DEFAULT 'local',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_releases (
  version     TEXT PRIMARY KEY,
  channel     TEXT NOT NULL DEFAULT 'stable',
  url         TEXT NOT NULL,
  sha256      TEXT NOT NULL,
  notes       TEXT NOT NULL DEFAULT '',
  published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS live_query_results (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  query_id    TEXT NOT NULL,
  status      TEXT NOT NULL,
  output      TEXT NOT NULL DEFAULT '',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO meta (key, value) VALUES ('schema_version', '1')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

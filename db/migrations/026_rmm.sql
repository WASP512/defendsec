-- Datto RMM collector (slice 8): Windows inventory, patch state and findings
-- gathered through the RMM's read-only API, with nothing installed on the PCs.
--
-- Every statement is idempotent: migration files re-run on every start (see
-- migrations.go).

-- Where a device row came from. 'agent' is a DefendSec agent (the default, and
-- every row that exists today); 'rmm' is a device read from Datto RMM. RMM rows
-- live in Postgres only: apid does not load them into the agent store, so no
-- agent code path (commands, isolation, heartbeat, the distro matcher) ever
-- treats one as an enrolled agent.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'agent';

-- An RMM device that is the same machine as an agent device points at it. It is
-- left out of the host list and the host counts (the agent row stands for the
-- machine), but keeps its own findings, so a machine reported by both sources
-- shows once and carries both sources' facts.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS merged_into TEXT;
CREATE INDEX IF NOT EXISTS devices_merged_into_idx ON devices (merged_into) WHERE merged_into IS NOT NULL;
CREATE INDEX IF NOT EXISTS devices_source_idx ON devices (source) WHERE source <> 'agent';

-- One instance reads one RMM site. api_url is the platform's API host
-- (https://<platform>-api.centrastage.net); the key and secret are never here,
-- they come from files named in apid's environment.
CREATE TABLE IF NOT EXISTS rmm_settings (
  id               INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  provider         TEXT NOT NULL DEFAULT 'datto' CHECK (provider = 'datto'),
  site_uid         TEXT NOT NULL DEFAULT '',
  site_name        TEXT NOT NULL DEFAULT '',
  -- A device whose last RMM audit is older than this has its software and
  -- patch evidence treated as missing, never as clean.
  stale_after_days INT NOT NULL DEFAULT 7 CHECK (stale_after_days BETWEEN 1 AND 90),
  selected_by      TEXT NOT NULL DEFAULT '',
  selected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- What RMM said about a device the last time it was read. One row per device
-- row of source 'rmm'.
CREATE TABLE IF NOT EXISTS rmm_devices (
  device_id       TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  rmm_uid         TEXT NOT NULL UNIQUE,
  site_uid        TEXT NOT NULL,
  hostname        TEXT NOT NULL DEFAULT '',
  serial          TEXT NOT NULL DEFAULT '',
  os_caption      TEXT NOT NULL DEFAULT '',
  os_version      TEXT NOT NULL DEFAULT '',
  os_build        TEXT NOT NULL DEFAULT '',
  os_display      TEXT NOT NULL DEFAULT '',
  os_install_type TEXT NOT NULL DEFAULT '',
  device_type     TEXT NOT NULL DEFAULT '',
  online          BOOLEAN NOT NULL DEFAULT false,
  rmm_last_seen   TIMESTAMPTZ,
  last_audit_at   TIMESTAMPTZ,
  last_reboot_at  TIMESTAMPTZ,
  reboot_required BOOLEAN NOT NULL DEFAULT false,
  -- RMM's own summary: NoPolicy, NoData, RebootRequired, InstallError,
  -- ApprovedPending, FullyPatched. Counts of patches by install status.
  patch_status             TEXT NOT NULL DEFAULT '',
  patches_approved_pending INT NOT NULL DEFAULT 0,
  patches_not_approved     INT NOT NULL DEFAULT 0,
  patches_installed        INT NOT NULL DEFAULT 0,
  antivirus_product        TEXT NOT NULL DEFAULT '',
  antivirus_status         TEXT NOT NULL DEFAULT '',
  software_count           INT NOT NULL DEFAULT 0,
  -- 'serial' or 'hostname' when this machine is also an enrolled agent.
  agent_device_id TEXT,
  dedupe_basis    TEXT NOT NULL DEFAULT '',
  -- Why this device's patch evidence could not be collected on the last read
  -- ('' when it was).
  collect_error   TEXT NOT NULL DEFAULT '',
  collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rmm_devices_agent_idx ON rmm_devices (agent_device_id) WHERE agent_device_id IS NOT NULL;

-- The patches RMM lists for a device as not installed (approved and pending, or
-- not yet approved), replaced wholesale on every read. kb is "KB<digits>", or
-- '' for an update that carries no KB (a driver, a definition update).
CREATE TABLE IF NOT EXISTS rmm_patches (
  device_id      TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  patch_uid      TEXT NOT NULL,
  kb             TEXT NOT NULL DEFAULT '',
  title          TEXT NOT NULL DEFAULT '',
  severity       TEXT NOT NULL DEFAULT 'UNSPECIFIED',
  patch_type     TEXT NOT NULL DEFAULT '',
  install_status TEXT NOT NULL CHECK (install_status IN ('APPROVED_PENDING', 'NOT_APPROVED')),
  release_date   DATE,
  reboot_required BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (device_id, patch_uid)
);
CREATE INDEX IF NOT EXISTS rmm_patches_kb_idx ON rmm_patches (kb) WHERE kb <> '';

-- What the last patch match examined for a host. A host with no findings is
-- only clean when coverage is 'covered':
--   covered   fresh RMM evidence, matched against a loaded MSRC feed
--   stale     the RMM audit is older than the threshold: missing evidence
--   no_data   RMM has no audit for it, or its patches could not be read
--   no_feed   no MSRC feed is loaded, so a missing KB cannot be mapped to CVEs
CREATE TABLE IF NOT EXISTS host_patch_state (
  device_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  source       TEXT NOT NULL DEFAULT 'datto-rmm',
  coverage     TEXT NOT NULL CHECK (coverage IN ('covered', 'stale', 'no_data', 'no_feed')),
  reason       TEXT NOT NULL DEFAULT '',
  evidence_at  TIMESTAMPTZ,
  kbs_missing  INT NOT NULL DEFAULT 0,
  kbs_mapped   INT NOT NULL DEFAULT 0,
  snapshot_id  BIGINT REFERENCES feed_snapshots(id),
  matched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per read of the RMM site. status:
--   ok            every device read
--   partial       some devices could not be read (see errors)
--   not_assessed  the run could not start or was cut short (credentials
--                 refused, no permission, rate limited); reason says why
CREATE TABLE IF NOT EXISTS rmm_syncs (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  site_uid      TEXT NOT NULL,
  triggered_by  TEXT NOT NULL DEFAULT 'schedule',
  started_at    TIMESTAMPTZ NOT NULL,
  finished_at   TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'not_assessed')),
  reason        TEXT NOT NULL DEFAULT '',
  devices       INT NOT NULL DEFAULT 0,
  windows       INT NOT NULL DEFAULT 0,
  skipped       INT NOT NULL DEFAULT 0,
  stale         INT NOT NULL DEFAULT 0,
  unreadable    INT NOT NULL DEFAULT 0,
  merged        INT NOT NULL DEFAULT 0,
  kbs_missing   INT NOT NULL DEFAULT 0,
  kbs_unmapped  INT NOT NULL DEFAULT 0,
  findings_open INT NOT NULL DEFAULT 0,
  requests      INT NOT NULL DEFAULT 0,
  errors        JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(errors) = 'array')
);
CREATE INDEX IF NOT EXISTS rmm_syncs_finished_idx ON rmm_syncs (finished_at DESC);

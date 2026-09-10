-- DefendSec Phase 7: alerts + richer FIM events

CREATE TABLE IF NOT EXISTS alerts (
  id          TEXT PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  hostname    TEXT NOT NULL DEFAULT '',
  kind        TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'medium',
  title       TEXT NOT NULL,
  summary     TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'open',
  source_type TEXT NOT NULL DEFAULT '',
  source_id   TEXT NOT NULL DEFAULT '',
  detail      JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status);
CREATE INDEX IF NOT EXISTS alerts_created_idx ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_device_idx ON alerts (device_id);
CREATE INDEX IF NOT EXISTS alerts_kind_idx ON alerts (kind);

ALTER TABLE fim_events ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'modified';
ALTER TABLE fim_events ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'medium';

INSERT INTO meta (key, value) VALUES ('schema_version', '2')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

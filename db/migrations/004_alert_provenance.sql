-- DefendSec: alert provenance (detected vs ingested time + generator)

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS generator_id TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS generator_version TEXT NOT NULL DEFAULT '';

UPDATE alerts SET ingested_at = created_at WHERE ingested_at IS NULL;
UPDATE alerts SET detected_at = created_at WHERE detected_at IS NULL;

INSERT INTO meta (key, value) VALUES ('schema_version', '4')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

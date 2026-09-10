CREATE TABLE IF NOT EXISTS saved_queries (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  query       TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO meta (key, value) VALUES ('schema_version', '3')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

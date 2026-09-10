#!/usr/bin/env bash
# DefendSec Cloud Agent start: per-boot reconciliation. Idempotent; returns
# after bringing PostgreSQL up and seeding deterministic dev credentials.
# Long-running services (console, apid, agent) run as terminals.
set -euo pipefail

cd "$(dirname "$0")/.."

# Bring the native PostgreSQL cluster online (no-op if already running).
sudo pg_ctlcluster 16 main start 2>/dev/null || true
for _ in $(seq 1 30); do
  if pg_isready -h 127.0.0.1 -q; then break; fi
  sleep 1
done

# Ensure the defendsec role and database exist (apid auto-applies migrations).
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='defendsec'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE ROLE defendsec LOGIN PASSWORD 'defendsec';"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='defendsec'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE DATABASE defendsec OWNER defendsec;"

# Seed the console store with a fixed dev enroll secret so the console, apid,
# and the local demo agent all agree on first boot. Never overwrite an
# existing store (DefendSec refuses to clobber its own state file).
mkdir -p data
if [ ! -f data/defendsec.json ]; then
  cat > data/defendsec.json <<'JSON'
{
  "schemaVersion": 2,
  "enrollSecret": "defendsec-dev-enroll",
  "devices": [],
  "fimEvents": [],
  "triages": []
}
JSON
fi

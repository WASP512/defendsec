#!/usr/bin/env bash
# DefendSec Cloud Agent install: idempotent dependency + build refresh.
# Runs after the repo is checked out. Must terminate; no long-running processes.
set -euo pipefail

cd "$(dirname "$0")/.."

# 1. Native PostgreSQL for the optional durable store (Phase 4+).
#    The repo defaults to native Postgres (no Docker) to avoid nested-container
#    issues; docker-compose remains an alternative for hosts that want it.
if ! command -v pg_ctlcluster >/dev/null 2>&1; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client
fi

# 2. Next.js console dependencies (reproducible from the committed lockfile).
npm ci

# 3. Go control plane (defendsec-apid) and host agent (defendsec-agentd).
make apid agent

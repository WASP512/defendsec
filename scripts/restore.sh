#!/usr/bin/env bash
set -euo pipefail
ARCHIVE="${1:?usage: restore.sh backup.tar.gz}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
mkdir -p "$ROOT/data"
cp -a "$SRC/defendsec.json" "$ROOT/data/" 2>/dev/null || true
cp -a "$SRC/defendsec-agents.json" "$ROOT/data/" 2>/dev/null || true
cp -a "$SRC/commands.json" "$ROOT/data/" 2>/dev/null || true
cp -a "$SRC/admin-token.txt" "$ROOT/data/" 2>/dev/null || true
if [[ -d "$SRC/pki" ]]; then
  rm -rf "$ROOT/data/pki"
  cp -a "$SRC/pki" "$ROOT/data/pki"
fi
if [[ -f "$SRC/postgres.sql" && -n "${DEFENDSEC_DATABASE_URL:-${DATABASE_URL:-}}" ]]; then
  URL="${DEFENDSEC_DATABASE_URL:-$DATABASE_URL}"
  psql "$URL" < "$SRC/postgres.sql"
fi
echo "restore complete from $ARCHIVE"

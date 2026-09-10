#!/usr/bin/env bash
set -euo pipefail
ARCHIVE="${1:?usage: restore.sh backup.tar.gz}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${DEFENDSEC_DATA_DIR:-${DATA_DIR:-$ROOT/data}}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
[[ -n "$SRC" && -d "$SRC" ]] || { echo "backup archive has no top-level directory" >&2; exit 1; }
mkdir -p "$DATA_DIR"
for name in defendsec.json defendsec.json.bak defendsec-agents.json commands.json admin-token.txt saved-queries.json; do
  [[ -e "$SRC/$name" ]] && cp -a "$SRC/$name" "$DATA_DIR/"
done
if [[ -d "$SRC/pki" ]]; then
  rm -rf "$DATA_DIR/pki"
  cp -a "$SRC/pki" "$DATA_DIR/pki"
fi
if [[ -f "$SRC/postgres.sql" && -n "${DEFENDSEC_DATABASE_URL:-${DATABASE_URL:-}}" ]]; then
  URL="${DEFENDSEC_DATABASE_URL:-$DATABASE_URL}"
  psql "$URL" < "$SRC/postgres.sql"
fi
echo "restore complete from $ARCHIVE"

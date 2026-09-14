#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${DEFENDSEC_DATA_DIR:-${DATA_DIR:-$ROOT/data}}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-$DATA_DIR/backups/defendsec-$STAMP}"
mkdir -p "$OUT"
for name in defendsec.json defendsec.json.bak defendsec-agents.json commands.json admin-token.txt saved-queries.json; do
  [[ -e "$DATA_DIR/$name" ]] && cp -a "$DATA_DIR/$name" "$OUT/"
done
[[ -d "$DATA_DIR/pki" ]] && cp -a "$DATA_DIR/pki" "$OUT/pki"
if [[ -n "${DEFENDSEC_DATABASE_URL:-${DATABASE_URL:-}}" ]]; then
  URL="${DEFENDSEC_DATABASE_URL:-$DATABASE_URL}"
  pg_dump "$URL" > "$OUT/postgres.sql"
fi
tar -C "$(dirname "$OUT")" -czf "${OUT}.tar.gz" "$(basename "$OUT")"
rm -rf "$OUT"

RETENTION_DAYS="${DEFENDSEC_BACKUP_RETENTION_DAYS:-14}"
find "$(dirname "$OUT")" -maxdepth 1 -name 'defendsec-*.tar.gz' -mtime "+$RETENTION_DAYS" -delete 2>/dev/null || true

echo "backup written to ${OUT}.tar.gz"

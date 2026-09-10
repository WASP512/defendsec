#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-$ROOT/data/backups/defendsec-$STAMP}"
mkdir -p "$OUT"
cp -a "$ROOT/data/defendsec.json" "$OUT/" 2>/dev/null || true
cp -a "$ROOT/data/defendsec-agents.json" "$OUT/" 2>/dev/null || true
cp -a "$ROOT/data/commands.json" "$OUT/" 2>/dev/null || true
cp -a "$ROOT/data/admin-token.txt" "$OUT/" 2>/dev/null || true
cp -a "$ROOT/data/pki" "$OUT/pki" 2>/dev/null || true
if [[ -n "${DEFENDSEC_DATABASE_URL:-${DATABASE_URL:-}}" ]]; then
  URL="${DEFENDSEC_DATABASE_URL:-$DATABASE_URL}"
  pg_dump "$URL" > "$OUT/postgres.sql"
fi
tar -C "$(dirname "$OUT")" -czf "${OUT}.tar.gz" "$(basename "$OUT")"
echo "backup written to ${OUT}.tar.gz"

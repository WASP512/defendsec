#!/usr/bin/env bash
# Regenerate the checked-in DefendSec technical white paper PDF.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT}/docs/DEFENDSEC_WHITE_PAPER.html"
OUTPUT="${ROOT}/docs/DefendSec-Technical-White-Paper.pdf"

browser=""
if [[ -x /opt/google/chrome/chrome ]]; then
  browser=/opt/google/chrome/chrome
else
  for candidate in google-chrome chromium chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      browser="$(command -v "$candidate")"
      break
    fi
  done
fi

if [[ -z "$browser" ]]; then
  echo "Google Chrome or Chromium is required to build the white paper." >&2
  exit 1
fi

[[ -f "$SOURCE" ]] || {
  echo "White paper source not found: $SOURCE" >&2
  exit 1
}

tmp="$(mktemp --suffix=.pdf)"
profile="$(mktemp -d)"
trap 'rm -f "$tmp"; rm -rf "$profile"' EXIT
rm -f "$tmp"

timeout 90 "$browser" \
  --headless \
  --no-sandbox \
  --disable-gpu \
  --disable-dev-shm-usage \
  --disable-background-networking \
  --no-first-run \
  --user-data-dir="$profile" \
  --print-to-pdf="$tmp" \
  --no-pdf-header-footer \
  "file://${SOURCE}" >/dev/null 2>&1

[[ -s "$tmp" ]] || {
  echo "Browser did not produce a PDF." >&2
  exit 1
}

install -m 0644 "$tmp" "$OUTPUT"
printf 'Wrote %s\n' "$OUTPUT"

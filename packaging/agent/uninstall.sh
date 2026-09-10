#!/usr/bin/env bash
# DefendSec — uninstall the host agent (does not touch a control-plane install).
#
# Usage:
#   sudo bash packaging/agent/uninstall.sh
#   sudo bash packaging/agent/uninstall.sh --purge-data

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

STATE_DIR="${DEFENDSEC_STATE_DIR:-/var/lib/defendsec-agent}"
INSTALL_BIN="${DEFENDSEC_INSTALL_BIN:-/usr/local/bin/defendsec-agentd}"
PURGE_DATA=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --purge-data) PURGE_DATA=1; shift ;;
    -h|--help)
      sed -n '1,12p' "$0"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

info() { printf '==> %s\n' "$*"; }

info "Stopping defendsec-agentd"
systemctl stop defendsec-agentd 2>/dev/null || true
systemctl disable defendsec-agentd 2>/dev/null || true
rm -f /etc/systemd/system/defendsec-agentd.service
systemctl daemon-reload
systemctl reset-failed defendsec-agentd 2>/dev/null || true

rm -f "$INSTALL_BIN"
rm -f /etc/defendsec/enroll-secret /etc/defendsec/agentd.env

if [[ "$PURGE_DATA" == "1" ]]; then
  info "Removing ${STATE_DIR}"
  rm -rf "$STATE_DIR"
else
  info "Left agent state in ${STATE_DIR} (pass --purge-data to remove it)"
fi

if [[ -d /etc/defendsec ]] && [[ -z "$(ls -A /etc/defendsec 2>/dev/null || true)" ]]; then
  rmdir /etc/defendsec 2>/dev/null || true
fi

info "Agent uninstall complete"

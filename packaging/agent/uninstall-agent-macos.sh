#!/bin/bash
# DefendSec — uninstall the host agent from macOS.
#
#   sudo defendsec-agent-uninstall [--purge-data]
#   sudo bash uninstall-agent-macos.sh [--purge-data]
#
# Agent state (certificate and key) is kept unless --purge-data is given.
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

LABEL="com.defendsec.agentd"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SUPPORT_DIR="/Library/Application Support/DefendSec"
PURGE=0
case "${1:-}" in
  --purge-data) PURGE=1 ;;
  "") ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
info() { printf '==> %s\n' "$*"; }

info "Stopping the agent"
launchctl bootout "system/${LABEL}" 2>/dev/null || true
rm -f "$PLIST" /usr/local/bin/defendsec-agentd
rm -f "${SUPPORT_DIR}/enroll-secret"
pkgutil --forget com.defendsec.agent >/dev/null 2>&1 || true

if [[ "$PURGE" -eq 1 ]]; then
  info "Removing agent state and logs"
  rm -rf "$SUPPORT_DIR" /Library/Logs/DefendSec
else
  info "Left agent state in ${SUPPORT_DIR}/agent (pass --purge-data to remove it)"
fi
rm -f /usr/local/bin/defendsec-agent-uninstall
info "Agent uninstall complete. Remove the host in the console to stop it being listed as offline."

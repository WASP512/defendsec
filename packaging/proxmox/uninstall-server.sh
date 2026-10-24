#!/usr/bin/env bash
# DefendSec — uninstall control plane (apid + console) from a Linux host / CT.
#
# Does not destroy a Proxmox container. On the PVE host use:
#   pct stop <CTID> && pct destroy <CTID>
#
# Usage:
#   sudo bash packaging/proxmox/uninstall-server.sh
#   sudo bash packaging/proxmox/uninstall-server.sh --purge-data
#   sudo bash packaging/proxmox/uninstall-server.sh --purge-data --purge-postgres
#
# --purge-data      remove /var/lib/defendsec, /opt/defendsec, /etc/defendsec
# --purge-postgres  drop the defendsec database and role (native Postgres only)

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

INSTALL_ROOT="${INSTALL_ROOT:-/opt/defendsec}"
DATA_DIR="${DATA_DIR:-/var/lib/defendsec}"
PURGE_DATA=0
PURGE_POSTGRES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-root) INSTALL_ROOT="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    --purge-data) PURGE_DATA=1; shift ;;
    --purge-postgres) PURGE_POSTGRES=1; shift ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

info() { printf '==> %s\n' "$*"; }

info "Stopping DefendSec server units"
units="defendsec-web defendsec-console defendsec-apid defendsec-feeds.timer defendsec-feeds.service defendsec-update.path defendsec-update.service"
# shellcheck disable=SC2086
systemctl stop $units 2>/dev/null || true
# shellcheck disable=SC2086
systemctl disable $units 2>/dev/null || true
for unit in defendsec-web defendsec-apid defendsec-console defendsec-feeds defendsec-update; do
  rm -f "/etc/systemd/system/${unit}.service"
  rm -rf "/etc/systemd/system/${unit}.service.d"
done
rm -f /etc/systemd/system/defendsec-feeds.timer /etc/systemd/system/defendsec-update.path
rm -rf /etc/systemd/system/defendsec-update.path.d
systemctl daemon-reload
# shellcheck disable=SC2086
systemctl reset-failed $units 2>/dev/null || true

# Close the ports install-server.sh opened, in whichever firewall it used.
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  info "Closing DefendSec ports in firewalld"
  for port in 47261 47262 47263; do
    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
  done
  firewall-cmd --reload >/dev/null 2>&1 || true
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  info "Closing DefendSec ports in ufw"
  ufw delete allow 47261:47263/tcp >/dev/null 2>&1 || true
fi

if command -v docker >/dev/null 2>&1; then
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx defendsec-postgres; then
    info "Removing Docker Postgres container defendsec-postgres"
    docker rm -f defendsec-postgres >/dev/null || true
  fi
fi

rm -f /usr/local/bin/defendsec-apid /usr/local/bin/defendsec-agentd /usr/local/bin/defendsec-web \
  /usr/local/bin/defendsec-feeds /usr/local/sbin/defendsec-update

if [[ "$PURGE_POSTGRES" == "1" ]] && command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
  info "Dropping native Postgres database and role defendsec"
  su -s /bin/bash postgres -c "psql -v ON_ERROR_STOP=1" <<'SQL' || true
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'defendsec' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS defendsec;
DROP ROLE IF EXISTS defendsec;
SQL
fi

if [[ "$PURGE_DATA" == "1" ]]; then
  info "Removing ${DATA_DIR}, ${INSTALL_ROOT}, /etc/defendsec"
  rm -rf "$DATA_DIR" "$INSTALL_ROOT" /etc/defendsec
else
  info "Left data in place (pass --purge-data to remove ${DATA_DIR}, ${INSTALL_ROOT}, /etc/defendsec)"
fi

info "Server uninstall complete"
echo "Proxmox CT removal (on the PVE host): pct stop <CTID> && pct destroy <CTID>"

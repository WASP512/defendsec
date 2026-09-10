#!/usr/bin/env bash
# DefendSec — Proxmox VE container bootstrap
#
# Run this on the Proxmox VE *host* (as root). It creates a Debian 12 LXC,
# then installs the DefendSec control plane (Postgres, apid, console).
#
# Usage:
#   bash packaging/proxmox/ct/defendsec.sh
#   CTID=120 HOSTNAME=defendsec bash packaging/proxmox/ct/defendsec.sh
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
#
# After install, enroll hosts with the printed agent one-liner (separate download).

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root on the Proxmox VE host." >&2
  exit 1
fi

if ! command -v pct >/dev/null 2>&1; then
  echo "pct not found — this script must run on a Proxmox VE host." >&2
  exit 1
fi

CTID="${CTID:-}"
HOSTNAME="${HOSTNAME:-defendsec}"
STORAGE="${STORAGE:-}"
BRIDGE="${BRIDGE:-vmbr0}"
CORES="${CORES:-2}"
MEMORY="${MEMORY:-2048}"
SWAP="${SWAP:-512}"
DISK="${DISK:-16}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"
REPO_URL="${REPO_URL:-https://github.com/WASP512/defendsec.git}"
REPO_REF="${REPO_REF:-main}"
INSTALL_URL="${INSTALL_URL:-}"
PASSWORD="${PASSWORD:-}"
# Forward GitHub auth into the CT for private clones.
GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

info() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

pick_ctid() {
  if [[ -n "$CTID" ]]; then
    echo "$CTID"
    return
  fi
  local id=200
  while pct status "$id" >/dev/null 2>&1; do
    id=$((id + 1))
  done
  echo "$id"
}

pick_storage() {
  if [[ -n "$STORAGE" ]]; then
    echo "$STORAGE"
    return
  fi
  # Prefer common local storages that support containers.
  local s
  for s in local-lvm local-zfs local; do
    if pvesm status 2>/dev/null | awk '{print $1}' | grep -qx "$s"; then
      echo "$s"
      return
    fi
  done
  pvesm status 2>/dev/null | awk 'NR>1 && $1!="" {print $1; exit}'
}

ensure_template() {
  local storage="$1"
  local tmpl
  tmpl="$(pveam list "$storage" 2>/dev/null | awk '/debian-12-standard/ {print $1; exit}')"
  if [[ -n "$tmpl" ]]; then
    echo "$tmpl"
    return
  fi
  info "Downloading Debian 12 LXC template to storage ${storage}"
  pveam update >/dev/null
  local remote
  remote="$(pveam available -section system 2>/dev/null | awk '/debian-12-standard_.*_amd64\.tar\.(xz|zst)/ {print $2; exit}')"
  [[ -n "$remote" ]] || die "could not find debian-12-standard template in pveam available"
  pveam download "$storage" "$remote"
  pveam list "$storage" 2>/dev/null | awk -v r="$remote" '$0 ~ r {print $1; exit}'
}

CTID="$(pick_ctid)"
STORAGE="$(pick_storage)"
[[ -n "$STORAGE" ]] || die "could not detect a Proxmox storage (set STORAGE=...)"

TEMPLATE="$(ensure_template "$STORAGE")"
[[ -n "$TEMPLATE" ]] || die "Debian 12 template missing"

if pct status "$CTID" >/dev/null 2>&1; then
  die "CT ${CTID} already exists — pick another CTID=..."
fi

ROOT_PW="${PASSWORD:-$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)}"

info "Creating CT ${CTID} (${HOSTNAME}) on ${STORAGE}"
CREATE_ARGS=(
  "$CTID"
  "$TEMPLATE"
  --hostname "$HOSTNAME"
  --cores "$CORES"
  --memory "$MEMORY"
  --swap "$SWAP"
  --rootfs "${STORAGE}:${DISK}"
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp"
  --unprivileged "$UNPRIVILEGED"
  --features nesting=1
  --onboot 1
  --startup order=10
  --password "$ROOT_PW"
)
if [[ -f /root/.ssh/authorized_keys ]]; then
  CREATE_ARGS+=(--ssh-public-keys /root/.ssh/authorized_keys)
fi

pct create "${CREATE_ARGS[@]}"
pct start "$CTID"

info "Waiting for network inside CT ${CTID}"
for _ in $(seq 1 60); do
  if pct exec "$CTID" -- bash -c 'getent hosts deb.debian.org >/dev/null 2>&1'; then
    break
  fi
  sleep 2
done

# Push or fetch install-server.sh
TMP_INSTALL="/tmp/defendsec-install-server.sh"
if [[ -n "$INSTALL_URL" ]]; then
  pct exec "$CTID" -- bash -c "curl -fsSL $(printf %q "$INSTALL_URL") -o ${TMP_INSTALL}"
elif [[ -f "$(dirname "$0")/../install-server.sh" ]]; then
  pct push "$CTID" "$(dirname "$0")/../install-server.sh" "$TMP_INSTALL"
else
  RAW="https://raw.githubusercontent.com/WASP512/defendsec/${REPO_REF}/packaging/proxmox/install-server.sh"
  pct exec "$CTID" -- bash -c "curl -fsSL $(printf %q "$RAW") -o ${TMP_INSTALL}"
fi

info "Installing DefendSec server inside CT ${CTID}"
pct exec "$CTID" -- env \
  GH_TOKEN="${GH_TOKEN}" \
  bash "$TMP_INSTALL" \
  --repo-url "$REPO_URL" \
  --repo-ref "$REPO_REF" \
  --advertise-hostname "$HOSTNAME"

IP="$(pct exec "$CTID" -- bash -c "hostname -I 2>/dev/null | awk '{print \$1}'" | tr -d '\r')"
info "DefendSec CT ${CTID} is ready"
cat <<EOF

Container:  ${CTID} (${HOSTNAME})
Root pass:  ${ROOT_PW}
Console:    http://${IP:-<ct-ip>}:47261
Enroll TLS: https://${IP:-<ct-ip>}:47262
gRPC:       ${IP:-<ct-ip>}:47263

Open the console, sign in with the admin token printed by the installer
(or /var/lib/defendsec/admin-token.txt inside the CT), then enroll agents
with the separate agent install one-liner from docs/INSTALL.md / Enroll page.

Enter CT:   pct enter ${CTID}
EOF

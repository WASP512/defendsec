#!/usr/bin/env bash
# DefendSec — Proxmox VE container bootstrap
#
# Run this on the Proxmox VE *host* (as root). It creates a Debian 12 LXC,
# then installs the DefendSec control plane (Postgres, apid, console).
#
# Usage:
#   bash packaging/proxmox/ct/defendsec.sh
#   CTID=120 CT_HOSTNAME=defendsec bash packaging/proxmox/ct/defendsec.sh
#   TEMPLATE_STORAGE=local STORAGE=local-lvm bash packaging/proxmox/ct/defendsec.sh
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
#
# After install, sign in at http://<ct-ip>:47261 and copy Agent install from Enroll.

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
# bash always sets HOSTNAME to this PVE host's name, so an inherited value that
# matches the host is not a user choice. CT_HOSTNAME is the explicit override.
PVE_HOSTNAME_SHORT="$(hostname -s 2>/dev/null || true)"
PVE_HOSTNAME_FQDN="$(hostname -f 2>/dev/null || true)"
CT_HOSTNAME="${CT_HOSTNAME:-}"
if [[ -z "$CT_HOSTNAME" ]]; then
  if [[ -n "${HOSTNAME:-}" && "$HOSTNAME" != "$PVE_HOSTNAME_SHORT" && "$HOSTNAME" != "$PVE_HOSTNAME_FQDN" ]]; then
    CT_HOSTNAME="$HOSTNAME"
  else
    CT_HOSTNAME="defendsec"
  fi
fi
STORAGE="${STORAGE:-}"
# LXC templates need directory storage with content=vztmpl (usually "local").
# CT disks typically live on LVM-thin (local-lvm). Do not reuse STORAGE for pveam.
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-}"
BRIDGE="${BRIDGE:-vmbr0}"
CORES="${CORES:-2}"
MEMORY="${MEMORY:-4096}"
SWAP="${SWAP:-512}"
DISK="${DISK:-24}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"
REPO_URL="${REPO_URL:-https://github.com/WASP512/defendsec.git}"
REPO_REF="${REPO_REF:-main}"
INSTALL_URL="${INSTALL_URL:-}"
PASSWORD="${PASSWORD:-}"
# Optional: GitHub auth for private forks or rate limits. Public clones need none.
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

storage_names() {
  pvesm status 2>/dev/null | awk 'NR>1 && $1 != "" && $1 != "Name" {print $1}'
}

storage_exists() {
  storage_names | grep -qx "$1"
}

storage_content_line() {
  pvesm config "$1" 2>/dev/null \
    | sed -n 's/^[[:space:]]*content[:]\{0,1\}[[:space:]]\{1,\}//p' \
    | head -n1
}

# 0 = supports type, 1 = does not, 2 = storage declares no content types.
storage_has_content() {
  local line want="$2" t
  line="$(storage_content_line "$1")"
  [[ -n "$line" ]] || return 2
  for t in ${line//,/ }; do
    [[ "$t" == "$want" ]] && return 0
  done
  return 1
}

first_storage_with_content() {
  local want="$1" s
  # Storages that explicitly declare the content type win.
  while read -r s; do
    if storage_has_content "$s" "$want"; then
      echo "$s"
      return 0
    fi
  done < <(storage_names)
  # Otherwise trust pvesm's own filter, but only for storages that declare none.
  local rc
  while read -r s; do
    rc=0
    storage_has_content "$s" "$want" || rc=$?
    if [[ "$rc" -eq 2 ]]; then
      echo "$s"
      return 0
    fi
  done < <(pvesm status --content "$want" 2>/dev/null | awk 'NR>1 && $1 != "" && $1 != "Name" {print $1}')
  return 1
}

pick_storage() {
  if [[ -n "$STORAGE" ]]; then
    echo "$STORAGE"
    return
  fi
  # Prefer storages that can hold CT disks (rootdir).
  local s
  for s in local-lvm local-zfs local; do
    if storage_exists "$s" && storage_has_content "$s" rootdir; then
      echo "$s"
      return
    fi
  done
  first_storage_with_content rootdir || true
}

pick_template_storage() {
  if [[ -n "$TEMPLATE_STORAGE" ]]; then
    echo "$TEMPLATE_STORAGE"
    return
  fi
  # pveam download requires content=vztmpl (typically the "local" dir storage).
  if storage_exists local && storage_has_content local vztmpl; then
    echo local
    return
  fi
  first_storage_with_content vztmpl || true
}

# Only the template volid may reach stdout here; the caller captures it.
ensure_template() {
  local storage="$1"
  local tmpl
  tmpl="$(pveam list "$storage" 2>/dev/null | awk '/debian-12-standard/ {print $1; exit}')"
  if [[ -n "$tmpl" ]]; then
    echo "$tmpl"
    return
  fi
  info "Downloading Debian 12 LXC template to storage ${storage}" >&2
  pveam update >/dev/null 2>&1 || true
  local remote
  remote="$(pveam available -section system 2>/dev/null | awk '/debian-12-standard_.*_amd64\.tar\.(xz|zst)/ {print $2; exit}')"
  [[ -n "$remote" ]] || die "could not find debian-12-standard template in pveam available"
  pveam download "$storage" "$remote" >&2 \
    || die "pveam download failed on ${storage} (set TEMPLATE_STORAGE to a vztmpl storage, usually local)"
  pveam list "$storage" 2>/dev/null | awk -v r="$remote" '$0 ~ r {print $1; exit}'
}

CTID="$(pick_ctid)"
STORAGE="$(pick_storage)"
[[ -n "$STORAGE" ]] || die "could not detect a Proxmox disk storage (set STORAGE=...)"
TEMPLATE_STORAGE="$(pick_template_storage)"
[[ -n "$TEMPLATE_STORAGE" ]] || die "could not detect a Proxmox template storage (set TEMPLATE_STORAGE=local)"

check_content_or_die() {
  local name="$1" want="$2" hint="$3" rc=0
  storage_has_content "$name" "$want" || rc=$?
  [[ "$rc" -eq 1 ]] && die "storage '${name}' does not support content type '${want}' — ${hint}"
  return 0
}
check_content_or_die "$STORAGE" rootdir "set STORAGE to a storage that holds CT disks (e.g. local-lvm)"
check_content_or_die "$TEMPLATE_STORAGE" vztmpl "set TEMPLATE_STORAGE to a template storage (usually local)"

TEMPLATE="$(ensure_template "$TEMPLATE_STORAGE" | tail -n1 | tr -d '\r')"
[[ -n "$TEMPLATE" ]] || die "Debian 12 template missing on ${TEMPLATE_STORAGE}"
[[ "$TEMPLATE" == *:vztmpl/* ]] \
  || die "unexpected template volid from ${TEMPLATE_STORAGE}: ${TEMPLATE}"

if pct status "$CTID" >/dev/null 2>&1; then
  die "CT ${CTID} already exists — pick another CTID=..."
fi

ROOT_PW="${PASSWORD:-$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)}"

info "Creating CT ${CTID} (${CT_HOSTNAME}) disk=${STORAGE} template=${TEMPLATE}"
CREATE_ARGS=(
  "$CTID"
  "$TEMPLATE"
  --hostname "$CT_HOSTNAME"
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
install_succeeded=0
on_exit() {
  local rc=$?
  if [[ "$rc" -ne 0 && "$install_succeeded" -ne 1 ]]; then
    cat >&2 <<EOF

DefendSec install stopped, but CT ${CTID} was left in place.
Inspect it: pct enter ${CTID}
Remove it:  pct stop ${CTID}; pct destroy ${CTID}
EOF
  fi
}
trap on_exit EXIT
pct start "$CTID"

info "Waiting for network inside CT ${CTID}"
net_ok=0
for _ in $(seq 1 60); do
  if pct exec "$CTID" -- bash -c 'getent hosts deb.debian.org >/dev/null 2>&1'; then
    net_ok=1
    break
  fi
  sleep 2
done
[[ "$net_ok" -eq 1 ]] || die "CT ${CTID} has no DNS/network after 2 minutes (check DHCP on ${BRIDGE})"

TMP_INSTALL="/tmp/defendsec-install-server.sh"

host_http_get() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    die "need curl or wget on the Proxmox host to fetch ${url}"
  fi
}

# Debian 12 standard LXC has no curl. Fetch on the PVE host (which does) and pct push.
push_install_script() {
  local src="" tmp=""
  local script_dir
  if ! script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"; then
    script_dir=""
  fi
  if [[ -n "$INSTALL_URL" ]]; then
    tmp="$(mktemp)"
    host_http_get "$INSTALL_URL" "$tmp"
    src="$tmp"
  elif [[ -n "$script_dir" && -f "${script_dir}/../install-server.sh" ]]; then
    src="${script_dir}/../install-server.sh"
  else
    tmp="$(mktemp)"
    host_http_get "https://raw.githubusercontent.com/WASP512/defendsec/${REPO_REF}/packaging/proxmox/install-server.sh" "$tmp"
    src="$tmp"
  fi
  [[ -s "$src" ]] || die "install-server.sh is empty"
  pct push "$CTID" "$src" "$TMP_INSTALL"
  if [[ -n "$tmp" ]]; then
    rm -f "$tmp"
  fi
}

info "Copying server installer into CT ${CTID}"
push_install_script

info "Installing DefendSec server inside CT ${CTID}"
pct exec "$CTID" -- env \
  GH_TOKEN="${GH_TOKEN}" \
  bash "$TMP_INSTALL" \
  --repo-url "$REPO_URL" \
  --repo-ref "$REPO_REF" \
  --advertise-hostname "$CT_HOSTNAME"

IP="$(pct exec "$CTID" -- bash -c "hostname -I 2>/dev/null | awk '{print \$1}'" | tr -d '\r')"
install_succeeded=1
info "DefendSec CT ${CTID} is ready"
cat <<EOF

Container:  ${CTID} (${CT_HOSTNAME})
Root pass:  ${ROOT_PW}
Console:    http://${IP:-<ct-ip>}:47261
Enroll TLS: https://${IP:-<ct-ip>}:47262
gRPC:       ${IP:-<ct-ip>}:47263

Admin token: pct exec ${CTID} -- cat /var/lib/defendsec/admin-token.txt
Sign in, then copy the separate agent command from the Enroll page.

Enter CT:   pct enter ${CTID}
EOF

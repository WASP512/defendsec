#!/usr/bin/env bash
# DefendSec — host agent installer (separate from the server/Proxmox script).
#
# Downloads defendsec-agentd from your DefendSec server (or GitHub Releases),
# installs the binary + systemd unit, and enrolls with the control plane.
#
# Usage:
#   curl -fsSL http://SERVER:47261/downloads/install-agent.sh | sudo bash -s -- \
#     --server-http https://SERVER:47262 \
#     --server-grpc SERVER:47263 \
#     --tls-server-name SERVER \
#     --enroll-secret SECRET \
#     --download-base http://SERVER:47261/downloads
#
# Offline / local binary:
#   sudo bash install-agent.sh --binary ./defendsec-agentd --enroll-secret SECRET ...

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

SERVER_HTTP="${DEFENDSEC_SERVER_HTTP:-}"
SERVER_GRPC="${DEFENDSEC_SERVER_GRPC:-}"
TLS_SERVER_NAME="${DEFENDSEC_TLS_SERVER_NAME:-}"
ENROLL_SECRET="${DEFENDSEC_ENROLL_SECRET:-}"
DOWNLOAD_BASE="${DEFENDSEC_DOWNLOAD_BASE:-}"
GITHUB_REPO="${DEFENDSEC_GITHUB_REPO:-WASP512/defendsec}"
BINARY_PATH=""
STATE_DIR="${DEFENDSEC_STATE_DIR:-/var/lib/defendsec-agent}"
INSTALL_BIN="${DEFENDSEC_INSTALL_BIN:-/usr/local/bin/defendsec-agentd}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-http) SERVER_HTTP="$2"; shift 2 ;;
    --server-grpc) SERVER_GRPC="$2"; shift 2 ;;
    --tls-server-name) TLS_SERVER_NAME="$2"; shift 2 ;;
    --enroll-secret) ENROLL_SECRET="$2"; shift 2 ;;
    --download-base) DOWNLOAD_BASE="$2"; shift 2 ;;
    --github-repo) GITHUB_REPO="$2"; shift 2 ;;
    --binary) BINARY_PATH="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '1,25p' "$0"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

[[ -n "$SERVER_HTTP" ]] || die "--server-http is required"
[[ -n "$SERVER_GRPC" ]] || die "--server-grpc is required"
[[ -n "$TLS_SERVER_NAME" ]] || die "--tls-server-name is required"
[[ -n "$ENROLL_SECRET" ]] || die "--enroll-secret is required"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

fetch_binary() {
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || die "binary not found: $BINARY_PATH"
    cp "$BINARY_PATH" "$TMPDIR/defendsec-agentd"
    chmod 0755 "$TMPDIR/defendsec-agentd"
    return
  fi

  local name="defendsec-agentd-linux-${GOARCH}"
  if [[ -n "$DOWNLOAD_BASE" ]]; then
    info "Downloading ${name} from ${DOWNLOAD_BASE}"
    curl -fsSL "${DOWNLOAD_BASE%/}/${name}" -o "$TMPDIR/defendsec-agentd"
    chmod 0755 "$TMPDIR/defendsec-agentd"
    return
  fi

  info "Downloading latest GitHub release asset (${GITHUB_REPO})"
  local api url
  api="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
  url="$(curl -fsSL "$api" | jq -r --arg n "$name" '.assets[] | select(.name==$n) | .browser_download_url' | head -1)"
  [[ -n "$url" && "$url" != "null" ]] || die "no release asset named ${name}; pass --download-base or --binary"
  curl -fsSL "$url" -o "$TMPDIR/defendsec-agentd"
  chmod 0755 "$TMPDIR/defendsec-agentd"
}

install_packages_light() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get install -y --no-install-recommends ca-certificates curl jq >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl jq >/dev/null
  fi
}

write_config() {
  mkdir -p /etc/defendsec "$STATE_DIR"
  printf '%s\n' "$ENROLL_SECRET" >/etc/defendsec/enroll-secret
  chmod 600 /etc/defendsec/enroll-secret

  cat >/etc/defendsec/agentd.env <<EOF
DEFENDSEC_SERVER_HTTP=${SERVER_HTTP}
DEFENDSEC_SERVER_GRPC=${SERVER_GRPC}
DEFENDSEC_TLS_SERVER_NAME=${TLS_SERVER_NAME}
EOF
  chmod 640 /etc/defendsec/agentd.env
}

install_unit() {
  cat >/etc/systemd/system/defendsec-agentd.service <<EOF
[Unit]
Description=DefendSec mTLS host agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/defendsec/agentd.env
ExecStart=${INSTALL_BIN} \\
  -server-http \${DEFENDSEC_SERVER_HTTP} \\
  -server-grpc \${DEFENDSEC_SERVER_GRPC} \\
  -tls-server-name \${DEFENDSEC_TLS_SERVER_NAME} \\
  -enroll-secret-file /etc/defendsec/enroll-secret \\
  -state-dir ${STATE_DIR}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now defendsec-agentd
}

install_packages_light
fetch_binary
install -m 0755 "$TMPDIR/defendsec-agentd" "$INSTALL_BIN"
write_config
install_unit

info "Agent installed and started"
systemctl --no-pager --full status defendsec-agentd | sed -n '1,15p' || true
echo
echo "Check the DefendSec console Devices page for this host."
echo "Logs: journalctl -u defendsec-agentd -f"

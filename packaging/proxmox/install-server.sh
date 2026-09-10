#!/usr/bin/env bash
# DefendSec — install control plane (apid + console + Postgres) on a Linux host.
#
# Supported: Debian 12 / Ubuntu 22.04+ (Proxmox CT target). Fedora also works
# with dnf packages (same layout).
#
# Usage:
#   sudo bash packaging/proxmox/install-server.sh
#   sudo bash packaging/proxmox/install-server.sh --repo-url https://github.com/WASP512/defendsec.git
#
# Produces agent download artifacts under /var/lib/defendsec/downloads so hosts
# can install with packaging/agent/install.sh (separate from this server script).

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or via sudo)." >&2
  exit 1
fi

REPO_URL="${REPO_URL:-https://github.com/WASP512/defendsec.git}"
REPO_REF="${REPO_REF:-main}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/defendsec}"
DATA_DIR="${DATA_DIR:-/var/lib/defendsec}"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-${DATA_DIR}/downloads}"
ADVERTISE_HOSTNAME="${ADVERTISE_HOSTNAME:-}"
PG_PASSWORD="${PG_PASSWORD:-}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-root) INSTALL_ROOT="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; DOWNLOADS_DIR="${DATA_DIR}/downloads"; shift 2 ;;
    --advertise-hostname) ADVERTISE_HOSTNAME="$2"; shift 2 ;;
    --pg-password) PG_PASSWORD="$2"; shift 2 ;;
    --admin-token) ADMIN_TOKEN="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

info() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo unknown
  fi
}

OS_ID="$(detect_os)"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

if [[ -z "$PG_PASSWORD" ]]; then
  PG_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
fi
if [[ -z "$ADMIN_TOKEN" ]]; then
  ADMIN_TOKEN="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
fi
if [[ -z "$ADVERTISE_HOSTNAME" ]]; then
  ADVERTISE_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
fi
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TLS_HOSTS="${ADVERTISE_HOSTNAME}"
if [[ -n "$PRIMARY_IP" ]]; then
  TLS_HOSTS="${ADVERTISE_HOSTNAME},${PRIMARY_IP}"
fi

install_packages() {
  info "Installing packages (${OS_ID})"
  case "$OS_ID" in
    debian|ubuntu)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y --no-install-recommends \
        ca-certificates curl git jq make openssl \
        docker.io \
        golang-go nodejs npm \
        iptables
      systemctl enable --now docker || true
      ;;
    fedora|rhel|centos|rocky|almalinux)
      dnf install -y git jq make openssl golang nodejs npm docker iptables-nft
      systemctl enable --now docker || true
      ;;
    *)
      die "unsupported OS id=${OS_ID}; install git jq make go node npm docker manually, then re-run"
      ;;
  esac

  if ! command -v go >/dev/null 2>&1; then
    die "go toolchain missing after package install"
  fi
  if ! command -v npm >/dev/null 2>&1; then
    die "npm missing after package install"
  fi
  if ! command -v docker >/dev/null 2>&1; then
    die "docker missing after package install"
  fi
}

create_users_dirs() {
  info "Creating defendsec user and directories"
  if ! id defendsec >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin defendsec
  fi
  # Docker group for compose as defendsec if needed; apid runs as defendsec without docker.
  usermod -aG docker defendsec 2>/dev/null || true
  mkdir -p "$DATA_DIR" "$DOWNLOADS_DIR" /etc/defendsec "$INSTALL_ROOT"
  chown -R defendsec:defendsec "$DATA_DIR"
  chmod 750 "$DATA_DIR"
  chmod 755 "$DOWNLOADS_DIR"
}

clone_or_update_repo() {
  info "Fetching source ${REPO_URL}@${REPO_REF}"
  local auth_url="$REPO_URL"
  local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  if [[ -n "$token" && "$REPO_URL" =~ github.com[:/]+([^/]+)/([^/.]+) ]]; then
    local owner="${BASH_REMATCH[1]}"
    local name="${BASH_REMATCH[2]}"
    auth_url="https://x-access-token:${token}@github.com/${owner}/${name}.git"
  fi
  if [[ -d "${INSTALL_ROOT}/.git" ]]; then
    if [[ -n "$token" ]]; then
      git -C "$INSTALL_ROOT" remote set-url origin "$auth_url"
    fi
    git -C "$INSTALL_ROOT" fetch --depth 1 origin "$REPO_REF"
    git -C "$INSTALL_ROOT" checkout -B "$REPO_REF" "FETCH_HEAD"
  else
    rm -rf "$INSTALL_ROOT"
    git clone --depth 1 --branch "$REPO_REF" "$auth_url" "$INSTALL_ROOT"
    # Do not leave the token in the remotes file.
    git -C "$INSTALL_ROOT" remote set-url origin "$REPO_URL"
  fi
  chown -R defendsec:defendsec "$INSTALL_ROOT"
}

start_postgres() {
  info "Starting Postgres (Docker)"
  mkdir -p "${DATA_DIR}/postgres"
  chown -R 999:999 "${DATA_DIR}/postgres" 2>/dev/null || true
  if docker ps -a --format '{{.Names}}' | grep -qx defendsec-postgres; then
    docker start defendsec-postgres >/dev/null || true
  else
    docker run -d \
      --name defendsec-postgres \
      --restart unless-stopped \
      -e POSTGRES_USER=defendsec \
      -e POSTGRES_PASSWORD="$PG_PASSWORD" \
      -e POSTGRES_DB=defendsec \
      -p 127.0.0.1:5432:5432 \
      -v "${DATA_DIR}/postgres:/var/lib/postgresql/data" \
      postgres:16-alpine >/dev/null
  fi
  for _ in $(seq 1 60); do
    if docker exec defendsec-postgres pg_isready -U defendsec -d defendsec >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "Postgres did not become ready"
}

build_binaries() {
  if [[ "$SKIP_BUILD" == "1" ]]; then
    info "Skipping build (--skip-build)"
    return
  fi
  info "Building apid + agent (${GOARCH})"
  su -s /bin/bash defendsec -c "
    set -euo pipefail
    cd $(printf %q "$INSTALL_ROOT")
    export GOTOOLCHAIN=local
    go build -o bin/defendsec-apid ./cmd/defendsec-apid
    go build -o bin/defendsec-agentd ./cmd/defendsec-agentd
    GOOS=linux GOARCH=${GOARCH} go build -o bin/defendsec-agentd-linux-${GOARCH} ./cmd/defendsec-agentd
  "
  install -m 0755 "${INSTALL_ROOT}/bin/defendsec-apid" /usr/local/bin/defendsec-apid
  install -m 0755 "${INSTALL_ROOT}/bin/defendsec-agentd" /usr/local/bin/defendsec-agentd
}

build_console() {
  if [[ "$SKIP_BUILD" == "1" ]]; then
    return
  fi
  info "Building console (Next.js standalone)"
  su -s /bin/bash defendsec -c "
    set -euo pipefail
    cd $(printf %q "$INSTALL_ROOT")
    if [[ -f package-lock.json ]]; then
      npm ci
    else
      npm install
    fi
    npm run build
    mkdir -p .next/standalone/.next
    cp -a .next/static .next/standalone/.next/static
    if [[ -d public ]]; then
      cp -a public .next/standalone/public
    fi
  "
}

seed_secrets_and_downloads() {
  info "Writing env files + agent download bundle"
  local db_url="postgres://defendsec:${PG_PASSWORD}@127.0.0.1:5432/defendsec?sslmode=disable"

  cat >/etc/defendsec/apid.env <<EOF
DEFENDSEC_DATABASE_URL=${db_url}
DEFENDSEC_TLS_HOSTNAME=${TLS_HOSTS}
DEFENDSEC_ADMIN_TOKEN=${ADMIN_TOKEN}
EOF
  chmod 640 /etc/defendsec/apid.env
  chown root:defendsec /etc/defendsec/apid.env

  cat >/etc/defendsec/console.env <<EOF
NODE_ENV=production
PORT=47261
HOSTNAME=0.0.0.0
DATABASE_URL=${db_url}
DEFENDSEC_DATABASE_URL=${db_url}
DEFENDSEC_ADMIN_TOKEN=${ADMIN_TOKEN}
DEFENDSEC_APID_ADMIN=http://127.0.0.1:47264
DEFENDSEC_DOWNLOADS_DIR=${DOWNLOADS_DIR}
EOF
  chmod 640 /etc/defendsec/console.env
  chown root:defendsec /etc/defendsec/console.env

  # Ensure admin token file exists for operators who read the data dir.
  install -d -o defendsec -g defendsec -m 750 "$DATA_DIR"
  printf '%s\n' "$ADMIN_TOKEN" >"${DATA_DIR}/admin-token.txt"
  chown defendsec:defendsec "${DATA_DIR}/admin-token.txt"
  chmod 600 "${DATA_DIR}/admin-token.txt"

  # Agent download artifacts (separate from server install).
  mkdir -p "$DOWNLOADS_DIR"
  if [[ -f "${INSTALL_ROOT}/bin/defendsec-agentd-linux-${GOARCH}" ]]; then
    install -m 0755 "${INSTALL_ROOT}/bin/defendsec-agentd-linux-${GOARCH}" \
      "${DOWNLOADS_DIR}/defendsec-agentd-linux-${GOARCH}"
  fi
  if [[ -f "${INSTALL_ROOT}/packaging/agent/install.sh" ]]; then
    install -m 0644 "${INSTALL_ROOT}/packaging/agent/install.sh" \
      "${DOWNLOADS_DIR}/install-agent.sh"
  fi
  (
    cd "$DOWNLOADS_DIR"
    sha256sum defendsec-agentd-linux-${GOARCH} install-agent.sh >SHA256SUMS 2>/dev/null || true
  )
  chown -R defendsec:defendsec "$DOWNLOADS_DIR"
}

install_systemd_units() {
  info "Installing systemd units"
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-apid.service" /etc/systemd/system/defendsec-apid.service
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-console.service" /etc/systemd/system/defendsec-console.service

  # Point apid at DATA_DIR via drop-in.
  mkdir -p /etc/systemd/system/defendsec-apid.service.d
  cat >/etc/systemd/system/defendsec-apid.service.d/override.conf <<EOF
[Service]
EnvironmentFile=/etc/defendsec/apid.env
ExecStart=
ExecStart=/usr/local/bin/defendsec-apid \\
  -data-dir ${DATA_DIR} \\
  -http-addr 0.0.0.0:47262 \\
  -grpc-addr 0.0.0.0:47263 \\
  -admin-addr 127.0.0.1:47264 \\
  -db-url \${DEFENDSEC_DATABASE_URL} \\
  -tls-hostname \${DEFENDSEC_TLS_HOSTNAME} \\
  -admin-token \${DEFENDSEC_ADMIN_TOKEN}
ReadWritePaths=${DATA_DIR}
EOF

  systemctl daemon-reload
  systemctl enable --now defendsec-apid
  systemctl enable --now defendsec-console

  # Wait for enroll secret file to appear.
  for _ in $(seq 1 30); do
    if [[ -f "${DATA_DIR}/defendsec.json" ]]; then
      break
    fi
    sleep 1
  done
}

print_summary() {
  local enroll=""
  if [[ -f "${DATA_DIR}/defendsec.json" ]]; then
    enroll="$(jq -r .enrollSecret "${DATA_DIR}/defendsec.json" 2>/dev/null || true)"
  fi
  local host="${PRIMARY_IP:-$ADVERTISE_HOSTNAME}"
  cat <<EOF

DefendSec server install complete.

  Console:     http://${host}:47261
  Enroll TLS:  https://${host}:47262
  gRPC:        ${host}:47263
  Admin token: ${ADMIN_TOKEN}
  Postgres:    user=defendsec  password=${PG_PASSWORD}  (loopback only)

  Enroll secret: ${enroll:-"(start apid / check ${DATA_DIR}/defendsec.json)"}

Agent install (separate download — run on each host):

  curl -fsSL "http://${host}:47261/downloads/install-agent.sh" | sudo bash -s -- \\
    --server-http "https://${host}:47262" \\
    --server-grpc "${host}:47263" \\
    --tls-server-name "${ADVERTISE_HOSTNAME}" \\
    --enroll-secret "${enroll:-YOUR_ENROLL_SECRET}" \\
    --download-base "http://${host}:47261/downloads"

Docs: ${INSTALL_ROOT}/docs/INSTALL.md
EOF
}

install_packages
create_users_dirs
clone_or_update_repo
start_postgres
build_binaries
build_console
seed_secrets_and_downloads
install_systemd_units
print_summary

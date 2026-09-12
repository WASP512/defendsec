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
# Postgres defaults to native packages (recommended for Proxmox LXC). Optional:
#   --postgres docker
#
# Produces agent download artifacts under /var/lib/defendsec/downloads so hosts
# can install with packaging/agent/install.sh (separate from this server script).

set -euo pipefail

# Minimal Debian templates do not include en_US.UTF-8 even when the host passes
# that locale through pct exec. C.UTF-8 is always available on Debian 12.
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

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
ENROLL_SECRET="${ENROLL_SECRET:-}"
VIEWER_TOKEN="${VIEWER_TOKEN:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"
# native = system postgresql (default, works in Proxmox LXC). docker = optional.
POSTGRES_MODE="${POSTGRES_MODE:-native}"
# Debian 12 ships Go 1.19 and Node 18, both too old to build this repo. When the
# distro is behind, install upstream toolchains under /usr/local instead.
GO_MIN="${GO_MIN:-1.22.0}"
NODE_MIN="${NODE_MIN:-20.9.0}"
GO_VERSION="${GO_VERSION:-}"
NODE_VERSION="${NODE_VERSION:-}"
GO_BIN=""
GO_HAVE=""
NODE_BIN=""
NODE_HAVE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-root) INSTALL_ROOT="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; DOWNLOADS_DIR="${DATA_DIR}/downloads"; shift 2 ;;
    --advertise-hostname) ADVERTISE_HOSTNAME="$2"; shift 2 ;;
    --pg-password) PG_PASSWORD="$2"; shift 2 ;;
    --admin-token) ADMIN_TOKEN="$2"; shift 2 ;;
    --viewer-token) VIEWER_TOKEN="$2"; shift 2 ;;
    --postgres) POSTGRES_MODE="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: install-server.sh [options]
  --repo-url URL             source repository
  --repo-ref REF             source branch/tag (default: main)
  --install-root PATH        source/build directory (default: /opt/defendsec)
  --data-dir PATH            state directory (default: /var/lib/defendsec)
  --advertise-hostname NAME  TLS hostname/SAN
  --pg-password PASSWORD     set Postgres password (preserved on rerun)
  --admin-token TOKEN        set console admin token (preserved on rerun)
  --viewer-token TOKEN       enable a read-only viewer token
  --postgres native|docker   Postgres mode (default: native)
  --skip-build               use existing prebuilt bin/ and .next/ artifacts
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

STARTED_AT="$(date +%s)"
CURRENT_STAGE=0
TOTAL_STAGES=9
info() {
  local now elapsed
  now="$(date +%s)"
  elapsed=$((now - STARTED_AT))
  printf '\n==> [%02dm%02ds] %s\n' "$((elapsed / 60))" "$((elapsed % 60))" "$*"
}
stage() {
  CURRENT_STAGE=$((CURRENT_STAGE + 1))
  info "[${CURRENT_STAGE}/${TOTAL_STAGES}] $*"
}
die() { echo "error: $*" >&2; exit 1; }

case "$POSTGRES_MODE" in
  native|docker) ;;
  *) die "--postgres must be 'native' or 'docker' (got: ${POSTGRES_MODE})" ;;
esac

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

if [[ -z "$ADMIN_TOKEN" && -s "${DATA_DIR}/admin-token.txt" ]]; then
  ADMIN_TOKEN="$(tr -d '\r\n' <"${DATA_DIR}/admin-token.txt")"
fi
if [[ -z "$PG_PASSWORD" && -r /etc/defendsec/apid.env ]]; then
  PG_PASSWORD="$(sed -n 's|^DEFENDSEC_DATABASE_URL=postgres://defendsec:\([^@]*\)@.*|\1|p' \
    /etc/defendsec/apid.env | head -n1)"
fi
if [[ -z "$VIEWER_TOKEN" && -r /etc/defendsec/apid.env ]]; then
  VIEWER_TOKEN="$(sed -n 's/^DEFENDSEC_VIEWER_TOKEN=//p' /etc/defendsec/apid.env | head -n1)"
fi

if [[ -z "$PG_PASSWORD" ]]; then
  PG_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
fi
if [[ -z "$ADMIN_TOKEN" ]]; then
  ADMIN_TOKEN="$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)"
fi
if [[ -z "$ENROLL_SECRET" ]]; then
  ENROLL_SECRET="$(openssl rand -hex 12)"
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
  info "Installing packages (${OS_ID}, postgres=${POSTGRES_MODE})"
  case "$OS_ID" in
    debian|ubuntu)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq make openssl xz-utils tar \
        iptables
      if [[ "$POSTGRES_MODE" == "native" ]]; then
        apt-get install -y --no-install-recommends postgresql postgresql-contrib
      else
        apt-get install -y --no-install-recommends docker.io
        systemctl enable --now docker || true
      fi
      ;;
    fedora|rhel|centos|rocky|almalinux)
      dnf install -y ca-certificates curl wget git jq make openssl xz tar iptables-nft
      if [[ "$POSTGRES_MODE" == "native" ]]; then
        dnf install -y postgresql-server postgresql
      else
        dnf install -y docker
        systemctl enable --now docker || true
      fi
      ;;
    *)
      die "unsupported OS id=${OS_ID}; install git jq make curl tar xz (+ postgresql) manually, then re-run"
      ;;
  esac

  if [[ "$POSTGRES_MODE" == "docker" ]] && ! command -v docker >/dev/null 2>&1; then
    die "docker missing after package install (use --postgres native)"
  fi
  if [[ "$POSTGRES_MODE" == "native" ]] && ! command -v psql >/dev/null 2>&1; then
    die "postgresql missing after package install"
  fi
}

# Pad to major.minor.patch so 1.22 and 1.22.0 compare equal.
normalize_version() {
  local v="${1#v}"
  v="${v#go}"
  v="${v%%[-+ ]*}"
  local IFS=.
  read -r -a parts <<<"$v"
  printf '%s.%s.%s' "${parts[0]:-0}" "${parts[1]:-0}" "${parts[2]:-0}"
}

# Compare dotted versions: succeeds when $1 >= $2.
version_ge() {
  local a b
  a="$(normalize_version "$1")"
  b="$(normalize_version "$2")"
  [[ "$a" == "$b" ]] && return 0
  [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$b" ]]
}

fetch_to() {
  local url="$1" dest="$2"
  echo "    Downloading ${url}"
  curl -fL --progress-bar "$url" -o "$dest" \
    || wget --show-progress -O "$dest" "$url" \
    || die "download failed: ${url}"
}

verify_sha256() {
  local file="$1" want="$2" got
  [[ -n "$want" ]] || die "no checksum published for $(basename "$file")"
  got="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$got" == "$want" ]] || die "checksum mismatch for $(basename "$file")"
}

# These set GO_BIN/NODE_BIN as globals, so they must not be called from a
# command substitution: the subshell would discard the path and later steps
# would build with an empty interpreter.
detect_go() {
  GO_BIN=""
  GO_HAVE=""
  local go_cmd
  for go_cmd in /usr/local/go/bin/go "$(command -v go 2>/dev/null || true)"; do
    if [[ -n "$go_cmd" && -x "$go_cmd" ]]; then
      GO_BIN="$go_cmd"
      GO_HAVE="$("$go_cmd" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
      return
    fi
  done
}

detect_node() {
  NODE_BIN=""
  NODE_HAVE=""
  local node_cmd
  for node_cmd in /usr/local/bin/node "$(command -v node 2>/dev/null || true)"; do
    if [[ -n "$node_cmd" && -x "$node_cmd" ]]; then
      NODE_BIN="$node_cmd"
      NODE_HAVE="$("$node_cmd" --version 2>/dev/null | sed 's/^v//')"
      return
    fi
  done
}

ensure_go() {
  # go.mod is authoritative once the source is present.
  if [[ -f "${INSTALL_ROOT}/go.mod" ]]; then
    local want
    want="$(awk '/^go[[:space:]]+[0-9]/ {print $2; exit}' "${INSTALL_ROOT}/go.mod")"
    if [[ -n "$want" ]]; then
      [[ "$want" == *.*.* ]] || want="${want}.0"
      version_ge "$want" "$GO_MIN" && GO_MIN="$want"
    fi
  fi

  local have
  detect_go
  have="$GO_HAVE"
  if [[ -n "$have" ]] && version_ge "$have" "$GO_MIN"; then
    info "Using Go ${have} (${GO_BIN})"
    return
  fi

  local ver="$GO_VERSION"
  if [[ -z "$ver" ]]; then
    ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -n1 || true)"
  fi
  [[ -n "$ver" ]] || ver="go1.24.6"
  [[ "$ver" == go* ]] || ver="go${ver}"

  info "Installing ${ver} (need >= ${GO_MIN}, found ${have:-none})"
  local file="${ver}.linux-${GOARCH}.tar.gz"
  local tmp="/tmp/${file}" sum=""
  sum="$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' 2>/dev/null \
    | jq -r --arg f "$file" '.[].files[]? | select(.filename == $f) | .sha256' | head -n1 || true)"
  fetch_to "https://go.dev/dl/${file}" "$tmp"
  verify_sha256 "$tmp" "$sum"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmp"
  rm -f "$tmp"

  GO_BIN=/usr/local/go/bin/go
  [[ -x "$GO_BIN" ]] || die "Go install failed"
  info "Using Go $("$GO_BIN" version | awk '{print $3}') (${GO_BIN})"
}

ensure_node() {
  local have
  detect_node
  have="$NODE_HAVE"
  if [[ -n "$have" ]] && version_ge "$have" "$NODE_MIN" && command -v npm >/dev/null 2>&1; then
    info "Using Node ${have} (${NODE_BIN})"
    return
  fi

  local node_arch
  case "$GOARCH" in
    amd64) node_arch=x64 ;;
    arm64) node_arch=arm64 ;;
    *) die "unsupported Node architecture: ${GOARCH}" ;;
  esac

  local ver="$NODE_VERSION"
  if [[ -z "$ver" ]]; then
    ver="$(curl -fsSL https://nodejs.org/dist/index.json 2>/dev/null \
      | jq -r '[.[] | select(.lts != false)][0].version' 2>/dev/null || true)"
  fi
  [[ -n "$ver" && "$ver" != "null" ]] || ver="v22.20.0"
  [[ "$ver" == v* ]] || ver="v${ver}"

  info "Installing Node ${ver} (need >= ${NODE_MIN}, found ${have:-none})"
  local name="node-${ver}-linux-${node_arch}"
  local tmp="/tmp/${name}.tar.xz" sum=""
  sum="$(curl -fsSL "https://nodejs.org/dist/${ver}/SHASUMS256.txt" 2>/dev/null \
    | awk -v f="${name}.tar.xz" '$2 == f {print $1; exit}' || true)"
  fetch_to "https://nodejs.org/dist/${ver}/${name}.tar.xz" "$tmp"
  verify_sha256 "$tmp" "$sum"

  mkdir -p /usr/local/lib/nodejs
  rm -rf "/usr/local/lib/nodejs/${name}"
  tar -C /usr/local/lib/nodejs -xJf "$tmp"
  rm -f "$tmp"

  ln -sfn "/usr/local/lib/nodejs/${name}/bin/node" /usr/local/bin/node
  ln -sfn "/usr/local/lib/nodejs/${name}/bin/npm" /usr/local/bin/npm
  ln -sfn "/usr/local/lib/nodejs/${name}/bin/npx" /usr/local/bin/npx

  NODE_BIN=/usr/local/bin/node
  [[ -x "$NODE_BIN" ]] || die "Node install failed"
  info "Using Node $("$NODE_BIN" --version) (${NODE_BIN})"
}

ensure_toolchains() {
  if [[ "$SKIP_BUILD" == "1" ]]; then
    ensure_node
    return
  fi
  ensure_go
  ensure_node
}

create_users_dirs() {
  info "Creating defendsec user and directories"
  if ! id defendsec >/dev/null 2>&1; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin defendsec
  fi
  if [[ "$POSTGRES_MODE" == "docker" ]]; then
    usermod -aG docker defendsec 2>/dev/null || true
  fi
  mkdir -p "$DATA_DIR" "$DOWNLOADS_DIR" /etc/defendsec "$INSTALL_ROOT"
  chown -R defendsec:defendsec "$DATA_DIR"
  chmod 750 "$DATA_DIR"
  chmod 755 "$DOWNLOADS_DIR"
}

# The installer runs as root while $INSTALL_ROOT is owned by defendsec.
# Git 2.35+ treats that as "dubious ownership" and refuses fetch/checkout
# on every upgrade re-run unless we mark the tree safe for this invocation.
git_in_install_root() {
  git -c "safe.directory=${INSTALL_ROOT}" -C "$INSTALL_ROOT" "$@"
}

clone_or_update_repo() {
  info "Fetching source ${REPO_URL}@${REPO_REF}"
  local auth_url="$REPO_URL"
  local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  # Token is optional; public github.com/WASP512/defendsec clones unauthenticated.
  if [[ -n "$token" && "$REPO_URL" =~ github.com[:/]+([^/]+)/([^/.]+) ]]; then
    local owner="${BASH_REMATCH[1]}"
    local name="${BASH_REMATCH[2]}"
    auth_url="https://x-access-token:${token}@github.com/${owner}/${name}.git"
  fi
  if [[ -d "${INSTALL_ROOT}/.git" ]]; then
    if [[ -n "$token" ]]; then
      git_in_install_root remote set-url origin "$auth_url"
    fi
    git_in_install_root fetch --depth 1 origin "$REPO_REF"
    git_in_install_root checkout -B "$REPO_REF" "FETCH_HEAD"
    git_in_install_root remote set-url origin "$REPO_URL"
  else
    rm -rf "$INSTALL_ROOT"
    git clone --depth 1 --branch "$REPO_REF" "$auth_url" "$INSTALL_ROOT"
    git_in_install_root remote set-url origin "$REPO_URL"
  fi
  chown -R defendsec:defendsec "$INSTALL_ROOT"
}

start_postgres_native() {
  info "Starting Postgres (native)"
  case "$OS_ID" in
    fedora|rhel|centos|rocky|almalinux)
      if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]] && [[ ! -f /var/lib/pgsql/data/postgresql.conf ]]; then
        postgresql-setup --initdb 2>/dev/null || /usr/bin/postgresql-setup --initdb || true
      fi
      systemctl enable --now postgresql
      ;;
    *)
      systemctl enable --now postgresql
      ;;
  esac

  local postgres_ready=0
  for attempt in $(seq 1 30); do
    if su -s /bin/bash postgres -c "cd /tmp && psql -tAc 'SELECT 1'" >/dev/null 2>&1; then
      postgres_ready=1
      echo "    Postgres service is ready."
      break
    fi
    if (( attempt == 1 || attempt % 5 == 0 )); then
      echo "    Waiting for Postgres service (${attempt}/30)…"
    fi
    sleep 1
  done
  [[ "$postgres_ready" -eq 1 ]] || die "Postgres did not become ready within 30 seconds"

  local esc
  esc="$(printf "%s" "$PG_PASSWORD" | sed "s/'/''/g")"
  su -s /bin/bash postgres -c "cd /tmp && psql -v ON_ERROR_STOP=1" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'defendsec') THEN
    CREATE ROLE defendsec LOGIN PASSWORD '${esc}';
  ELSE
    ALTER ROLE defendsec WITH LOGIN PASSWORD '${esc}';
  END IF;
END
\$\$;
SELECT 'CREATE DATABASE defendsec OWNER defendsec'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'defendsec')\gexec
GRANT ALL PRIVILEGES ON DATABASE defendsec TO defendsec;
SQL

  # Allow password auth on local TCP (apid uses 127.0.0.1, not peer/socket).
  local confhba
  confhba="$(su -s /bin/bash postgres -c "cd /tmp && psql -tAc 'SHOW hba_file'" | tr -d '[:space:]')"
  if [[ -n "$confhba" && -f "$confhba" ]]; then
    if ! grep -qE '^[[:space:]]*host[[:space:]]+defendsec[[:space:]]+defendsec[[:space:]]+127\.0\.0\.1/32[[:space:]]+(scram-sha-256|md5)' "$confhba"; then
      printf '\nhost defendsec defendsec 127.0.0.1/32 scram-sha-256\n' >>"$confhba"
      systemctl reload postgresql || systemctl restart postgresql
      sleep 2
    fi
  fi

  for attempt in $(seq 1 30); do
    if PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -U defendsec -d defendsec -tAc 'SELECT 1' >/dev/null 2>&1; then
      echo "    Database login verified."
      return
    fi
    if (( attempt == 1 || attempt % 5 == 0 )); then
      echo "    Waiting for database login (${attempt}/30)…"
    fi
    sleep 1
  done
  die "native Postgres did not accept defendsec@127.0.0.1 connections"
}

start_postgres_docker() {
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
  for attempt in $(seq 1 60); do
    if docker exec defendsec-postgres pg_isready -U defendsec -d defendsec >/dev/null 2>&1; then
      echo "    Docker Postgres is ready."
      return
    fi
    if (( attempt == 1 || attempt % 5 == 0 )); then
      echo "    Waiting for Docker Postgres (${attempt}/60)…"
    fi
    sleep 1
  done
  die "Postgres did not become ready"
}

start_postgres() {
  if [[ "$POSTGRES_MODE" == "docker" ]]; then
    start_postgres_docker
  else
    start_postgres_native
  fi
}

build_binaries() {
  if [[ "$SKIP_BUILD" != "1" ]]; then
    local release_version
    release_version="$(git_in_install_root describe --tags --always 2>/dev/null || echo dev)"
    if [[ "$release_version" =~ ^v[0-9] ]]; then
      release_version="${release_version#v}"
    fi
    [[ -x "$GO_BIN" ]] || die "Go toolchain not resolved; rerun the installer"
    info "Building apid + agent (${GOARCH}) with $("$GO_BIN" version | awk '{print $3}')"
    su -s /bin/bash defendsec -c "
      set -euo pipefail
      cd $(printf %q "$INSTALL_ROOT")
      export GOTOOLCHAIN=local
      export PATH=$(printf %q "$(dirname "$GO_BIN")"):\$PATH
      export GOPATH=$(printf %q "${DATA_DIR}/go")
      export GOCACHE=$(printf %q "${DATA_DIR}/go/cache")
      go build -o bin/defendsec-apid ./cmd/defendsec-apid
      go build -ldflags $(printf %q "-X main.agentVersion=${release_version}") -o bin/defendsec-agentd ./cmd/defendsec-agentd
      GOOS=linux GOARCH=amd64 go build -ldflags $(printf %q "-X main.agentVersion=${release_version}") -o bin/defendsec-agentd-linux-amd64 ./cmd/defendsec-agentd
      GOOS=linux GOARCH=arm64 go build -ldflags $(printf %q "-X main.agentVersion=${release_version}") -o bin/defendsec-agentd-linux-arm64 ./cmd/defendsec-agentd
    "
  else
    info "Skipping build (--skip-build)"
  fi
  [[ -x "${INSTALL_ROOT}/bin/defendsec-apid" ]] || die "missing prebuilt bin/defendsec-apid"
  [[ -x "${INSTALL_ROOT}/bin/defendsec-agentd" ]] || die "missing prebuilt bin/defendsec-agentd"
  [[ -x "${INSTALL_ROOT}/bin/defendsec-agentd-linux-amd64" ]] || die "missing prebuilt amd64 agent"
  [[ -x "${INSTALL_ROOT}/bin/defendsec-agentd-linux-arm64" ]] || die "missing prebuilt arm64 agent"
  install -m 0755 "${INSTALL_ROOT}/bin/defendsec-apid" /usr/local/bin/defendsec-apid
  install -m 0755 "${INSTALL_ROOT}/bin/defendsec-agentd" /usr/local/bin/defendsec-agentd
  if [[ ! -s "${INSTALL_ROOT}/VERSION" ]]; then
    local installed_version
    installed_version="$(git_in_install_root describe --tags --always 2>/dev/null || echo dev)"
    if [[ "$installed_version" =~ ^v[0-9] ]]; then
      installed_version="${installed_version#v}"
    fi
    printf '%s\n' "$installed_version" >"${INSTALL_ROOT}/VERSION"
  fi
}

build_console() {
  if [[ "$SKIP_BUILD" == "1" ]]; then
    [[ -f "${INSTALL_ROOT}/.next/standalone/server.js" ]] \
      || die "--skip-build requested but .next/standalone/server.js is missing"
    ln -sfn "${INSTALL_ROOT}/.next/standalone" "${INSTALL_ROOT}/current-console"
    return
  fi
  [[ -x "$NODE_BIN" ]] || die "Node toolchain not resolved; rerun the installer"
  info "Building console (Next.js standalone) with Node $("$NODE_BIN" --version)"
  su -s /bin/bash defendsec -c "
    set -euo pipefail
    cd $(printf %q "$INSTALL_ROOT")
    export PATH=$(printf %q "$(dirname "$NODE_BIN")"):\$PATH
    export npm_config_cache=$(printf %q "${DATA_DIR}/npm-cache")
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
  ln -sfn "${INSTALL_ROOT}/.next/standalone" "${INSTALL_ROOT}/current-console"
}

seed_secrets_and_downloads() {
  info "Writing env files + agent download bundle"
  local db_url="postgres://defendsec:${PG_PASSWORD}@127.0.0.1:5432/defendsec?sslmode=disable"
  local server_version
  server_version="$(tr -d '\r\n' <"${INSTALL_ROOT}/VERSION" 2>/dev/null || echo dev)"

  # apid needs the enroll secret before it can start, while the console requires
  # apid. Seed their shared store to avoid a first-boot dependency cycle.
  if [[ -f "${DATA_DIR}/defendsec.json" ]]; then
    local existing_enroll
    existing_enroll="$(jq -er '.enrollSecret | select(type == "string" and length > 0)' \
      "${DATA_DIR}/defendsec.json" 2>/dev/null)" \
      || die "${DATA_DIR}/defendsec.json exists but has no valid enrollSecret; restore or remove it"
    ENROLL_SECRET="$existing_enroll"
  else
    jq -n --arg secret "$ENROLL_SECRET" \
      '{schemaVersion: 2, enrollSecret: $secret, devices: [], fimEvents: [], triages: []}' \
      >"${DATA_DIR}/defendsec.json"
    chown defendsec:defendsec "${DATA_DIR}/defendsec.json"
    chmod 640 "${DATA_DIR}/defendsec.json"
  fi

  cat >/etc/defendsec/apid.env <<EOF
DEFENDSEC_DATABASE_URL=${db_url}
DEFENDSEC_TLS_HOSTNAME=${TLS_HOSTS}
DEFENDSEC_ADMIN_TOKEN=${ADMIN_TOKEN}
DEFENDSEC_ENROLL_SECRET=${ENROLL_SECRET}
DEFENDSEC_VIEWER_TOKEN=${VIEWER_TOKEN}
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
DEFENDSEC_VIEWER_TOKEN=${VIEWER_TOKEN}
DEFENDSEC_APID_ADMIN=http://127.0.0.1:47264
DEFENDSEC_DOWNLOADS_DIR=${DOWNLOADS_DIR}
DEFENDSEC_DATA_DIR=${DATA_DIR}
DEFENDSEC_VERSION=${server_version}
DEFENDSEC_UPDATE_REPO=WASP512/defendsec
# The packaged console is served directly over HTTP. Set true behind an HTTPS proxy.
DEFENDSEC_COOKIE_SECURE=false
EOF
  chmod 640 /etc/defendsec/console.env
  chown root:defendsec /etc/defendsec/console.env

  cat >/etc/defendsec/update.env <<EOF
DEFENDSEC_INSTALL_ROOT=${INSTALL_ROOT}
DEFENDSEC_DATA_DIR=${DATA_DIR}
DEFENDSEC_UPDATE_REPO=WASP512/defendsec
EOF
  chmod 640 /etc/defendsec/update.env
  chown root:defendsec /etc/defendsec/update.env

  install -d -o defendsec -g defendsec -m 750 "$DATA_DIR"
  printf '%s\n' "$ADMIN_TOKEN" >"${DATA_DIR}/admin-token.txt"
  chown defendsec:defendsec "${DATA_DIR}/admin-token.txt"
  chmod 600 "${DATA_DIR}/admin-token.txt"

  mkdir -p "$DOWNLOADS_DIR"
  local agent_arch
  for agent_arch in amd64 arm64; do
    if [[ -f "${INSTALL_ROOT}/bin/defendsec-agentd-linux-${agent_arch}" ]]; then
      install -m 0755 "${INSTALL_ROOT}/bin/defendsec-agentd-linux-${agent_arch}" \
        "${DOWNLOADS_DIR}/defendsec-agentd-linux-${agent_arch}"
    fi
  done
  if [[ -f "${INSTALL_ROOT}/packaging/agent/install.sh" ]]; then
    install -m 0644 "${INSTALL_ROOT}/packaging/agent/install.sh" \
      "${DOWNLOADS_DIR}/install-agent.sh"
  fi
  (
    cd "$DOWNLOADS_DIR"
    sha256sum defendsec-agentd-linux-amd64 defendsec-agentd-linux-arm64 install-agent.sh \
      >SHA256SUMS
  )
  chown -R defendsec:defendsec "$DOWNLOADS_DIR"
}

install_systemd_units() {
  info "Installing systemd units"
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-apid.service" /etc/systemd/system/defendsec-apid.service
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-console.service" /etc/systemd/system/defendsec-console.service
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-update.service" /etc/systemd/system/defendsec-update.service
  install -m 0644 "${INSTALL_ROOT}/packaging/systemd/defendsec-update.path" /etc/systemd/system/defendsec-update.path
  install -m 0755 "${INSTALL_ROOT}/packaging/proxmox/update-server.sh" /usr/local/sbin/defendsec-update

  mkdir -p /etc/systemd/system/defendsec-update.path.d
  cat >/etc/systemd/system/defendsec-update.path.d/override.conf <<EOF
[Path]
PathExists=
PathExists=${DATA_DIR}/update-request.json
EOF

  # The shipped unit assumes /usr/bin/node; point it at the node we actually use.
  [[ -x "$NODE_BIN" ]] || die "Node toolchain not resolved; cannot write console unit"
  mkdir -p /etc/systemd/system/defendsec-console.service.d
  cat >/etc/systemd/system/defendsec-console.service.d/override.conf <<EOF
[Service]
WorkingDirectory=${INSTALL_ROOT}/current-console
ExecStart=
ExecStart=${NODE_BIN} server.js
ReadWritePaths=${INSTALL_ROOT} ${DATA_DIR}
EOF

  mkdir -p /etc/systemd/system/defendsec-apid.service.d
  cat >/etc/systemd/system/defendsec-apid.service.d/override.conf <<EOF
[Service]
WorkingDirectory=${INSTALL_ROOT}
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

  # After=postgresql when using native packages.
  if [[ "$POSTGRES_MODE" == "native" ]]; then
    mkdir -p /etc/systemd/system/defendsec-apid.service.d
    cat >/etc/systemd/system/defendsec-apid.service.d/postgres.conf <<EOF
[Unit]
After=postgresql.service
Requires=postgresql.service
EOF
  fi

  systemctl daemon-reload
  systemctl enable --now defendsec-update.path
  systemctl enable --now defendsec-apid
  systemctl enable --now defendsec-console

  local apid_ok=0 console_ok=0
  for attempt in $(seq 1 30); do
    if systemctl is-active --quiet defendsec-apid \
      && curl -kfsS https://127.0.0.1:47262/healthz >/dev/null; then
      apid_ok=1
      echo "    API health check passed."
      break
    fi
    if (( attempt == 1 || attempt % 5 == 0 )); then
      echo "    Waiting for API health check (${attempt}/30)…"
    fi
    sleep 1
  done
  if [[ "$apid_ok" -ne 1 ]]; then
    systemctl --no-pager --full status defendsec-apid || true
    journalctl -u defendsec-apid --no-pager -n 50 || true
    die "defendsec-apid failed its startup health check"
  fi

  for attempt in $(seq 1 30); do
    if systemctl is-active --quiet defendsec-console \
      && curl -fsS http://127.0.0.1:47261/login >/dev/null; then
      console_ok=1
      echo "    Console health check passed."
      break
    fi
    if (( attempt == 1 || attempt % 5 == 0 )); then
      echo "    Waiting for console health check (${attempt}/30)…"
    fi
    sleep 1
  done
  if [[ "$console_ok" -ne 1 ]]; then
    systemctl --no-pager --full status defendsec-console || true
    journalctl -u defendsec-console --no-pager -n 50 || true
    die "defendsec-console failed its startup health check"
  fi

  [[ -s "${DATA_DIR}/defendsec.json" ]] || die "apid is healthy but ${DATA_DIR}/defendsec.json is missing"
}

print_summary() {
  local host="${PRIMARY_IP:-$ADVERTISE_HOSTNAME}"
  cat <<EOF

DefendSec server install complete.

  Console:     http://${host}:47261
  Enroll TLS:  https://${host}:47262
  gRPC:        ${host}:47263
  Admin token: ${DATA_DIR}/admin-token.txt
  Postgres:    user=defendsec (127.0.0.1 only, mode=${POSTGRES_MODE})
               credentials: /etc/defendsec/apid.env

  Enroll secret: ${DATA_DIR}/defendsec.json

Open the console with the admin token, then copy the agent command from Enroll.

Docs: ${INSTALL_ROOT}/docs/INSTALL.md
EOF
}

info "Starting DefendSec server installer"
echo "OS=${OS_ID} architecture=${GOARCH} Postgres=${POSTGRES_MODE}"
echo "A first source build commonly takes 15–30 minutes. Keep this terminal open."
stage "Install operating-system packages"
install_packages
stage "Create service user and data directories"
create_users_dirs
stage "Download DefendSec source"
clone_or_update_repo
stage "Check and install Go / Node toolchains"
ensure_toolchains
stage "Start and configure Postgres"
start_postgres
stage "Build API and agent binaries"
build_binaries
stage "Install JavaScript packages and build console"
build_console
stage "Write configuration and agent downloads"
seed_secrets_and_downloads
stage "Install services and run health checks"
install_systemd_units
print_summary

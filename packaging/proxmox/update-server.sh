#!/usr/bin/env bash
# Apply a published DefendSec release on an existing packaged server.
#
# Normal operation is started by defendsec-update.service after the console
# writes /var/lib/defendsec/update-request.json. `verify-request` is a
# non-mutating mode used by release validation and tests.

set -euo pipefail

INSTALL_ROOT="${DEFENDSEC_INSTALL_ROOT:-/opt/defendsec}"
DATA_DIR="${DEFENDSEC_DATA_DIR:-/var/lib/defendsec}"
REQUEST_FILE="${DEFENDSEC_UPDATE_REQUEST:-${DATA_DIR}/update-request.json}"
STATUS_FILE="${DEFENDSEC_UPDATE_STATUS:-${DATA_DIR}/update-status.json}"
UPDATE_REPO="${DEFENDSEC_UPDATE_REPO:-WASP512/defendsec}"
MODE="${1:-apply}"
MAX_ASSET_BYTES=$((512 * 1024 * 1024))

die() {
  write_status failed "$1"
  echo "error: $1" >&2
  exit 1
}

write_status() {
  local state="$1" message="$2" version="${3:-}"
  [[ "$MODE" == "verify-request" ]] && return 0
  install -d -m 0750 -o defendsec -g defendsec "$DATA_DIR"
  local tmp="${STATUS_FILE}.tmp"
  jq -n \
    --arg state "$state" \
    --arg message "$message" \
    --arg version "$version" \
    --arg updatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{state:$state,message:$message,version:$version,updatedAt:$updatedAt}' >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$STATUS_FILE"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

valid_component() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ && "$1" != "." && "$1" != ".." ]]
}

download() {
  local url="$1" output="$2"
  if [[ "${DEFENDSEC_UPDATE_TEST_MODE:-0}" != "1" ]]; then
    [[ "$url" == https://github.com/"${UPDATE_REPO}"/releases/download/* ]] \
      || die "release asset URL is outside the configured repository"
  fi
  curl --fail --location --silent --show-error \
    --max-filesize "$MAX_ASSET_BYTES" \
    --output "$output" "$url"
}

asset_url() {
  local release_json="$1" name="$2"
  jq -er --arg name "$name" \
    '.assets[] | select(.name == $name) | .browser_download_url' "$release_json"
}

expected_sha() {
  local sums="$1" name="$2"
  awk -v name="$name" '
    {
      file=$2
      sub(/^\*/, "", file)
      if (file == name) { print tolower($1); found=1; exit }
    }
    END { if (!found) exit 1 }
  ' "$sums"
}

verify_file() {
  local sums="$1" name="$2" path="$3" want got
  want="$(expected_sha "$sums" "$name")" || die "SHA256SUMS has no entry for ${name}"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "invalid sha256 for ${name}"
  got="$(sha256sum "$path" | awk '{print tolower($1)}')"
  [[ "$got" == "$want" ]] || die "sha256 mismatch for ${name}"
}

safe_extract_console() {
  local archive="$1" destination="$2"
  if tar -tzf "$archive" | awk '
      /^\/|(^|\/)\.\.(\/|$)/ { bad=1 }
      END { exit bad ? 0 : 1 }
    '; then
    die "console archive contains an unsafe path"
  fi
  mkdir -p "$destination"
  tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$destination"
  [[ -f "${destination}/server.js" ]] || die "console archive is missing server.js"
}

create_backup() {
  local version="$1" stamp backup_dir archive database_url=""
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="${DATA_DIR}/backups/pre-upgrade-${version}-${stamp}"
  archive="${backup_dir}.tar.gz"
  mkdir -p "$backup_dir"
  chmod 0700 "$backup_dir"
  local name
  for name in defendsec.json defendsec.json.bak defendsec-agents.json commands.json \
    admin-token.txt saved-queries.json update-status.json; do
    [[ -e "${DATA_DIR}/${name}" ]] && cp -a "${DATA_DIR}/${name}" "$backup_dir/"
  done
  [[ -d "${DATA_DIR}/pki" ]] && cp -a "${DATA_DIR}/pki" "${backup_dir}/pki"

  database_url="${DEFENDSEC_DATABASE_URL:-${DATABASE_URL:-}}"
  if [[ -n "$database_url" ]]; then
    require_command pg_dump
    pg_dump --no-owner --no-privileges "$database_url" >"${backup_dir}/postgres.sql" \
      || die "Postgres backup failed; the update was not installed"
  fi
  tar -C "$(dirname "$backup_dir")" -czf "$archive" "$(basename "$backup_dir")"
  chmod 0600 "$archive"
  rm -rf "$backup_dir"
  printf '%s\n' "$archive"
}

prepare_release() {
  local request="$1" work="$2"
  local repo tag version api_url arch
  repo="$(jq -er '.repo' "$request")" || die "update request is missing repo"
  tag="$(jq -er '.tag' "$request")" || die "update request is missing tag"
  version="$(jq -er '.version' "$request")" || die "update request is missing version"
  [[ "$repo" == "$UPDATE_REPO" ]] || die "update request repository does not match configured repository"
  valid_component "$tag" || die "invalid release tag"
  valid_component "$version" || die "invalid release version"

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported server architecture: ${arch}" ;;
  esac

  if [[ "${DEFENDSEC_UPDATE_TEST_MODE:-0}" == "1" && -n "${DEFENDSEC_RELEASE_API_URL:-}" ]]; then
    api_url="$DEFENDSEC_RELEASE_API_URL"
  else
    api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  fi
  curl --fail --location --silent --show-error \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    --output "${work}/release.json" "$api_url"
  [[ "$(jq -r '.tag_name // ""' "${work}/release.json")" == "$tag" ]] \
    || die "release metadata tag does not match the request"

  local apid_name="defendsec-apid-linux-${arch}"
  local console_name="defendsec-console.tar.gz"
  local sums_name="SHA256SUMS"
  local name url
  for name in "$apid_name" "$console_name" "$sums_name" \
    "defendsec-agentd-linux-amd64" "defendsec-agentd-linux-arm64" \
    "install-agent.sh" "update-server.sh" "VERSION"; do
    url="$(asset_url "${work}/release.json" "$name")" || die "release is missing ${name}"
    download "$url" "${work}/${name}"
  done

  for name in "$apid_name" "$console_name" \
    "defendsec-agentd-linux-amd64" "defendsec-agentd-linux-arm64" \
    "install-agent.sh" "update-server.sh" "VERSION"; do
    verify_file "${work}/${sums_name}" "$name" "${work}/${name}"
  done
  [[ "$(<"${work}/VERSION")" == "$version" ]] || die "VERSION asset does not match requested release"
  safe_extract_console "${work}/${console_name}" "${work}/console"
  printf '%s\n%s\n' "$version" "$apid_name"
}

apply_release() {
  [[ "$(id -u)" -eq 0 ]] || die "server updates must run as root"
  [[ -s "$REQUEST_FILE" ]] || die "no pending update request"
  require_command flock
  exec 9>"${DATA_DIR}/update.lock"
  flock -n 9 || die "another server update is already running"

  local work version apid_name release_dir previous_console="" backup_path
  work="$(mktemp -d "${DATA_DIR}/update-work.XXXXXX")"
  trap 'rm -f "$REQUEST_FILE"; rm -rf "$work"' EXIT
  write_status downloading "Downloading and verifying release"
  mapfile -t prepared < <(prepare_release "$REQUEST_FILE" "$work")
  version="${prepared[0]:-}"
  apid_name="${prepared[1]:-}"
  [[ -n "$version" && -n "$apid_name" ]] || die "release preparation failed"

  write_status backing_up "Creating a pre-upgrade data and Postgres backup" "$version"
  backup_path="$(create_backup "$version")"

  release_dir="${INSTALL_ROOT}/releases/${version}"
  [[ ! -e "$release_dir" ]] || rm -rf "$release_dir"
  install -d -m 0755 "${INSTALL_ROOT}/releases"
  mv "${work}/console" "$release_dir"
  chown -R defendsec:defendsec "$release_dir"

  if [[ -L "${INSTALL_ROOT}/current-console" ]]; then
    previous_console="$(readlink "${INSTALL_ROOT}/current-console")"
  fi
  cp -a /usr/local/bin/defendsec-apid /usr/local/bin/defendsec-apid.bak
  install -m 0755 "${work}/${apid_name}" /usr/local/bin/defendsec-apid.new

  write_status installing "Installing release and restarting services" "$version"
  mv -f /usr/local/bin/defendsec-apid.new /usr/local/bin/defendsec-apid
  ln -sfn "$release_dir" "${INSTALL_ROOT}/current-console.new"
  mv -Tf "${INSTALL_ROOT}/current-console.new" "${INSTALL_ROOT}/current-console"

  install -d -m 0755 -o defendsec -g defendsec "${DATA_DIR}/downloads"
  install -m 0755 "${work}/defendsec-agentd-linux-amd64" "${DATA_DIR}/downloads/"
  install -m 0755 "${work}/defendsec-agentd-linux-arm64" "${DATA_DIR}/downloads/"
  install -m 0644 "${work}/install-agent.sh" "${DATA_DIR}/downloads/"
  (
    cd "${DATA_DIR}/downloads"
    sha256sum defendsec-agentd-linux-amd64 defendsec-agentd-linux-arm64 install-agent.sh >SHA256SUMS
  )
  chown -R defendsec:defendsec "${DATA_DIR}/downloads"
  printf '%s\n' "$version" >"${INSTALL_ROOT}/VERSION"
  chmod 0644 "${INSTALL_ROOT}/VERSION"

  systemctl restart defendsec-apid
  systemctl restart defendsec-console

  local healthy=0
  for _ in $(seq 1 40); do
    if systemctl is-active --quiet defendsec-apid \
      && systemctl is-active --quiet defendsec-console \
      && curl -kfsS https://127.0.0.1:47262/healthz >/dev/null \
      && curl -fsS http://127.0.0.1:47261/login >/dev/null; then
      healthy=1
      break
    fi
    sleep 1
  done
  if [[ "$healthy" -ne 1 ]]; then
    cp -a /usr/local/bin/defendsec-apid.bak /usr/local/bin/defendsec-apid
    if [[ -n "$previous_console" ]]; then
      ln -sfn "$previous_console" "${INSTALL_ROOT}/current-console.rollback"
      mv -Tf "${INSTALL_ROOT}/current-console.rollback" "${INSTALL_ROOT}/current-console"
    fi
    systemctl restart defendsec-apid || true
    systemctl restart defendsec-console || true
    die "release failed health checks; previous server binaries were restored"
  fi

  install -m 0755 "${work}/update-server.sh" /usr/local/sbin/defendsec-update
  rm -f "$REQUEST_FILE"
  write_status completed "Server update completed successfully; backup: ${backup_path}" "$version"
}

for command in curl jq sha256sum tar awk; do
  require_command "$command"
done

case "$MODE" in
  apply)
    apply_release
    ;;
  verify-request)
    request="${2:-$REQUEST_FILE}"
    [[ -s "$request" ]] || die "request file not found"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    prepare_release "$request" "$work" >/dev/null
    echo "release verification passed"
    ;;
  backup-only)
    create_backup "${2:-test}"
    ;;
  *)
    die "usage: $0 [apply|verify-request REQUEST|backup-only VERSION]"
    ;;
esac

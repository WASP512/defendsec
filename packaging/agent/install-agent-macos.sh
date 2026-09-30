#!/bin/bash
# DefendSec — host agent installer for macOS (roadmap 5.2).
#
# Installs defendsec-agentd as a launchd daemon running as root, and enrolls.
#
#   curl -fL https://SERVER:47261/downloads/install-agent-macos.sh -o /tmp/install-agent-macos.sh
#   sudo bash /tmp/install-agent-macos.sh \
#     --server-http https://SERVER:47262 --server-grpc SERVER:47263 \
#     --tls-server-name SERVER --enroll-secret SECRET \
#     --download-base https://SERVER:47261/downloads --download-ca /path/to/console.crt
#
# There is no option to skip certificate verification: the checksum travels
# over the same connection as the binary, so it cannot stand in for it.
#
# The process sensor on macOS samples the process table. Seeing every
# execution needs EndpointSecurity, which requires an Apple-granted
# entitlement; see docs/MACOS.md.

set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ "$(uname -s)" == "Darwin" ]] || { echo "This installer is for macOS." >&2; exit 1; }

SERVER_HTTP="" SERVER_GRPC="" TLS_SERVER_NAME="" ENROLL_SECRET=""
DOWNLOAD_BASE="" DOWNLOAD_CA="" BINARY_PATH=""
GITHUB_REPO="WASP512/defendsec"
INSTALL_BIN="/usr/local/bin/defendsec-agentd"
SUPPORT_DIR="/Library/Application Support/DefendSec"
STATE_DIR="${SUPPORT_DIR}/agent"
LOG_DIR="/Library/Logs/DefendSec"
LABEL="com.defendsec.agentd"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-http) SERVER_HTTP="$2"; shift 2 ;;
    --server-grpc) SERVER_GRPC="$2"; shift 2 ;;
    --tls-server-name) TLS_SERVER_NAME="$2"; shift 2 ;;
    --enroll-secret) ENROLL_SECRET="$2"; shift 2 ;;
    --download-base) DOWNLOAD_BASE="$2"; shift 2 ;;
    --download-ca) DOWNLOAD_CA="$2"; shift 2 ;;
    --github-repo) GITHUB_REPO="$2"; shift 2 ;;
    --binary) BINARY_PATH="$2"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

[[ -n "$SERVER_HTTP" && -n "$SERVER_GRPC" && -n "$TLS_SERVER_NAME" && -n "$ENROLL_SECRET" ]] ||
  die "--server-http, --server-grpc, --tls-server-name and --enroll-secret are required"

case "$(uname -m)" in
  x86_64) GOARCH=amd64 ;;
  arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
NAME="defendsec-agentd-darwin-${GOARCH}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl_tls=()
if [[ -n "$DOWNLOAD_CA" ]]; then
  [[ -f "$DOWNLOAD_CA" ]] || die "certificate not found: $DOWNLOAD_CA"
  curl_tls+=(--cacert "$DOWNLOAD_CA")
fi

if [[ -n "$BINARY_PATH" ]]; then
  cp "$BINARY_PATH" "$TMP/defendsec-agentd"
else
  if [[ -n "$DOWNLOAD_BASE" ]]; then
    bin_url="${DOWNLOAD_BASE%/}/${NAME}"; sums_url="${DOWNLOAD_BASE%/}/SHA256SUMS"
  else
    release="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest")"
    # No jq on a stock Mac; plutil can read JSON.
    printf '%s' "$release" >"$TMP/release.json"
    bin_url="" sums_url=""
    i=0
    while name="$(plutil -extract "assets.${i}.name" raw -o - "$TMP/release.json" 2>/dev/null)"; do
      url="$(plutil -extract "assets.${i}.browser_download_url" raw -o - "$TMP/release.json")"
      [[ "$name" == "$NAME" ]] && bin_url="$url"
      [[ "$name" == "SHA256SUMS" ]] && sums_url="$url"
      i=$((i + 1))
    done
    [[ -n "$bin_url" ]] || die "the latest release has no ${NAME}; pass --download-base or --binary"
    [[ -n "$sums_url" ]] || die "the latest release has no SHA256SUMS"
  fi
  info "Downloading ${NAME}"
  curl -fL --progress-bar "${curl_tls[@]}" "$bin_url" -o "$TMP/defendsec-agentd"
  curl -fL --progress-bar "${curl_tls[@]}" "$sums_url" -o "$TMP/SHA256SUMS"
  expected="$(awk -v n="$NAME" '$2 == n || $2 == "*" n {print $1; exit}' "$TMP/SHA256SUMS")"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "SHA256SUMS has no valid entry for ${NAME}"
  actual="$(shasum -a 256 "$TMP/defendsec-agentd" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || die "checksum mismatch for ${NAME}"
  info "Verified ${NAME} SHA256"
fi

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
  info "Stopping the existing agent"
  launchctl bootout "system/${LABEL}" 2>/dev/null || true
fi

info "Installing ${INSTALL_BIN}"
mkdir -p "$(dirname "$INSTALL_BIN")"
install -m 0755 "$TMP/defendsec-agentd" "$INSTALL_BIN"
xattr -d com.apple.quarantine "$INSTALL_BIN" 2>/dev/null || true
if [[ -f "$(dirname "$0")/uninstall-agent-macos.sh" ]]; then
  install -m 0755 "$(dirname "$0")/uninstall-agent-macos.sh" /usr/local/bin/defendsec-agent-uninstall
fi

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 700 "$SUPPORT_DIR" "$STATE_DIR"
umask 077
printf '%s\n' "$ENROLL_SECRET" >"${SUPPORT_DIR}/enroll-secret"
chmod 600 "${SUPPORT_DIR}/enroll-secret"

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' <<<"$1"; }
cat >"$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_BIN}</string>
    <string>-server-http</string><string>$(xml_escape "$SERVER_HTTP")</string>
    <string>-server-grpc</string><string>$(xml_escape "$SERVER_GRPC")</string>
    <string>-tls-server-name</string><string>$(xml_escape "$TLS_SERVER_NAME")</string>
    <string>-enroll-secret-file</string><string>${SUPPORT_DIR}/enroll-secret</string>
    <string>-state-dir</string><string>${STATE_DIR}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>${LOG_DIR}/agentd.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/agentd.log</string>
</dict>
</plist>
PLIST
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null || die "generated launchd plist is invalid"

info "Starting the agent and waiting for enrollment"
launchctl bootstrap system "$PLIST"
ok=0
for _ in $(seq 1 30); do
  if [[ -s "${STATE_DIR}/device-id" ]]; then ok=1; break; fi
  sleep 1
done
if [[ "$ok" -ne 1 ]]; then
  tail -n 40 "${LOG_DIR}/agentd.log" 2>/dev/null || true
  die "the agent did not enroll within 30 seconds"
fi
info "Agent installed, enrolled and running."
echo "Log: ${LOG_DIR}/agentd.log"
echo "Uninstall: sudo defendsec-agent-uninstall [--purge-data]"

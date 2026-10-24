#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ASSETS="${TMP}/assets"
mkdir -p "${ASSETS}/console"

BACKUP_DATA="${TMP}/data"
mkdir -p "${BACKUP_DATA}/pki"
printf '%s\n' '{"devices":[]}' >"${BACKUP_DATA}/defendsec.json"
printf '%s\n' 'test certificate' >"${BACKUP_DATA}/pki/ca.pem"
backup_path="$(
  DEFENDSEC_DATA_DIR="$BACKUP_DATA" \
    bash "${ROOT}/packaging/proxmox/update-server.sh" backup-only 1.2.3
)"
[[ -s "$backup_path" ]]
[[ "$(stat -c '%a' "$backup_path")" == "600" ]]
tar -tzf "$backup_path" | awk '
  /\/defendsec.json$/ { data=1 }
  /\/pki\/ca.pem$/ { pki=1 }
  END { exit (data && pki) ? 0 : 1 }
'

printf '%s\n' 'console fixture' >"${ASSETS}/console/server.js"
tar -C "${ASSETS}/console" -czf "${ASSETS}/defendsec-console.tar.gz" .
for name in defendsec-apid-linux-amd64 defendsec-apid-linux-arm64 \
  defendsec-web-linux-amd64 defendsec-web-linux-arm64 \
  defendsec-feeds-linux-amd64 defendsec-feeds-linux-arm64 \
  defendsec-agentd-linux-amd64 defendsec-agentd-linux-arm64; do
  printf '#!/usr/bin/env bash\necho %s\n' "$name" >"${ASSETS}/${name}"
  chmod +x "${ASSETS}/${name}"
done
cp "${ROOT}/packaging/agent/install.sh" "${ASSETS}/install-agent.sh"
cp "${ROOT}/packaging/proxmox/update-server.sh" "${ASSETS}/update-server.sh"
printf '%s\n' '1.2.3' >"${ASSETS}/VERSION"
(
  cd "$ASSETS"
  sha256sum defendsec-* install-agent.sh update-server.sh VERSION >SHA256SUMS
)

jq -n --arg base "file://${ASSETS}" '{
  tag_name: "v1.2.3",
  assets: [
    "defendsec-apid-linux-amd64",
    "defendsec-apid-linux-arm64",
    "defendsec-web-linux-amd64",
    "defendsec-web-linux-arm64",
    "defendsec-feeds-linux-amd64",
    "defendsec-feeds-linux-arm64",
    "defendsec-agentd-linux-amd64",
    "defendsec-agentd-linux-arm64",
    "defendsec-console.tar.gz",
    "install-agent.sh",
    "update-server.sh",
    "VERSION",
    "SHA256SUMS"
  ] | map({name: ., browser_download_url: ($base + "/" + .)})
}' >"${TMP}/release.json"

jq -n '{repo:"WASP512/defendsec",tag:"v1.2.3",version:"1.2.3"}' >"${TMP}/request.json"

DEFENDSEC_UPDATE_TEST_MODE=1 \
DEFENDSEC_RELEASE_API_URL="file://${TMP}/release.json" \
  bash "${ROOT}/packaging/proxmox/update-server.sh" verify-request "${TMP}/request.json"

# Every binary the update installs must be checked: tamper with each in turn
# (this host's architecture) and require a rejection, then restore it.
case "$(uname -m)" in
  aarch64|arm64) arch=arm64 ;;
  *) arch=amd64 ;;
esac
for bin in defendsec-apid defendsec-web defendsec-feeds; do
  asset="${ASSETS}/${bin}-linux-${arch}"
  cp "$asset" "${asset}.orig"
  printf '%s\n' 'tampered' >>"$asset"
  if DEFENDSEC_UPDATE_TEST_MODE=1 \
    DEFENDSEC_RELEASE_API_URL="file://${TMP}/release.json" \
    bash "${ROOT}/packaging/proxmox/update-server.sh" verify-request "${TMP}/request.json" >/dev/null 2>&1; then
    echo "tampered ${bin} unexpectedly passed verification" >&2
    exit 1
  fi
  mv -f "${asset}.orig" "$asset"
  echo "tampered ${bin} was rejected"
done

# A release with no web or feeds binary is refused, not half-installed.
jq 'del(.assets[] | select(.name | startswith("defendsec-feeds-linux-")))' "${TMP}/release.json" >"${TMP}/release-nofeeds.json"
if DEFENDSEC_UPDATE_TEST_MODE=1 \
  DEFENDSEC_RELEASE_API_URL="file://${TMP}/release-nofeeds.json" \
  bash "${ROOT}/packaging/proxmox/update-server.sh" verify-request "${TMP}/request.json" >/dev/null 2>&1; then
  echo "a release without defendsec-feeds unexpectedly passed verification" >&2
  exit 1
fi
echo "a release missing defendsec-feeds was rejected"


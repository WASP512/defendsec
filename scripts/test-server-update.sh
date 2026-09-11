#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ASSETS="${TMP}/assets"
mkdir -p "${ASSETS}/console"

printf '%s\n' 'console fixture' >"${ASSETS}/console/server.js"
tar -C "${ASSETS}/console" -czf "${ASSETS}/defendsec-console.tar.gz" .
for name in defendsec-apid-linux-amd64 defendsec-apid-linux-arm64 \
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

printf '%s\n' 'tampered' >>"${ASSETS}/defendsec-apid-linux-amd64"
case "$(uname -m)" in
  aarch64|arm64)
    printf '%s\n' 'tampered' >>"${ASSETS}/defendsec-apid-linux-arm64"
    ;;
esac
if DEFENDSEC_UPDATE_TEST_MODE=1 \
  DEFENDSEC_RELEASE_API_URL="file://${TMP}/release.json" \
  bash "${ROOT}/packaging/proxmox/update-server.sh" verify-request "${TMP}/request.json" >/dev/null 2>&1; then
  echo "tampered release unexpectedly passed verification" >&2
  exit 1
fi

echo "tampered release was rejected"


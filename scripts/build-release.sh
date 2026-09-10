#!/usr/bin/env bash
# Build release binaries for DefendSec (server + multi-arch agent downloads).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/dist}"
mkdir -p "$OUT"

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
echo "Building DefendSec ${version}"

build() {
  local os="$1" arch="$2" pkg="$3" outname="$4"
  echo "  -> ${outname}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "${OUT}/${outname}" "$pkg"
}

build linux amd64 ./cmd/defendsec-apid "defendsec-apid-linux-amd64"
build linux arm64 ./cmd/defendsec-apid "defendsec-apid-linux-arm64"
build linux amd64 ./cmd/defendsec-agentd "defendsec-agentd-linux-amd64"
build linux arm64 ./cmd/defendsec-agentd "defendsec-agentd-linux-arm64"

install -m 0644 packaging/agent/install.sh "${OUT}/install-agent.sh"
(
  cd "$OUT"
  sha256sum defendsec-* install-agent.sh >SHA256SUMS
)

echo
echo "Artifacts in ${OUT}:"
ls -la "$OUT"
echo
echo "Attach agent binaries + install-agent.sh + SHA256SUMS to a GitHub Release,"
echo "or copy them to /var/lib/defendsec/downloads on your server."

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
  local ldflags="-s -w"
  if [[ "$pkg" == "./cmd/defendsec-agentd" ]]; then
    ldflags="${ldflags} -X main.agentVersion=${version}"
  fi
  echo "  -> ${outname}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${OUT}/${outname}" "$pkg"
}

build linux amd64 ./cmd/defendsec-apid "defendsec-apid-linux-amd64"
build linux arm64 ./cmd/defendsec-apid "defendsec-apid-linux-arm64"
build linux amd64 ./cmd/defendsec-agentd "defendsec-agentd-linux-amd64"
build linux arm64 ./cmd/defendsec-agentd "defendsec-agentd-linux-arm64"

install -m 0644 packaging/agent/install.sh "${OUT}/install-agent.sh"
install -m 0755 packaging/proxmox/update-server.sh "${OUT}/update-server.sh"

echo "  -> defendsec-console.tar.gz"
npm ci
npm run build
mkdir -p .next/standalone/.next
cp -a .next/static .next/standalone/.next/static
if [[ -d public ]]; then
  cp -a public .next/standalone/public
fi
tar -C .next/standalone -czf "${OUT}/defendsec-console.tar.gz" .
printf '%s\n' "$version" >"${OUT}/VERSION"

(
  cd "$OUT"
  sha256sum defendsec-* install-agent.sh update-server.sh VERSION >SHA256SUMS
)

echo
echo "Artifacts in ${OUT}:"
ls -la "$OUT"
echo
echo "Attach every file in ${OUT} to a GitHub Release."

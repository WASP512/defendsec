#!/usr/bin/env bash
# Build release binaries for DefendSec (server + multi-arch agent downloads).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/dist}"
mkdir -p "$OUT"

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
release_version="$version"
if [[ "$release_version" =~ ^v[0-9] ]]; then
  release_version="${release_version#v}"
fi
echo "Building DefendSec ${version}"

# Reproducible builds (roadmap 5.7).
#
# Three flags carry the whole property, and the third is the one that is easy
# to miss:
#
#   -trimpath        strips the build directory, so a binary does not depend
#                    on where it was compiled.
#   CGO_ENABLED=0    no host toolchain, no host libc, so the output does not
#                    depend on the machine.
#   -buildvcs=false  Go stamps the git commit and dirty flag into a main
#                    package by default. That makes the binary depend on the
#                    presence of a .git directory — so somebody verifying
#                    from a released source tarball gets a different hash
#                    than CI produced, and the reproducibility claim fails
#                    for precisely the person most likely to test it. This
#                    was measured, not assumed: with VCS stamping on, the
#                    same source built with and without .git differs.
#
# The commit is not lost by turning stamping off — it is stamped explicitly
# below, which is deterministic because it is an input rather than something
# the toolchain discovers.
commit="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"

build() {
  local os="$1" arch="$2" pkg="$3" outname="$4"
  local ldflags="-s -w -X main.buildCommit=${commit}"
  if [[ "$pkg" == "./cmd/defendsec-agentd" ]]; then
    ldflags="${ldflags} -X main.agentVersion=${release_version}"
  fi
  echo "  -> ${outname}"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "${OUT}/${outname}" "$pkg"
}

build linux amd64 ./cmd/defendsec-apid "defendsec-apid-linux-amd64"
build linux arm64 ./cmd/defendsec-apid "defendsec-apid-linux-arm64"
build linux amd64 ./cmd/defendsec-agentd "defendsec-agentd-linux-amd64"
build linux arm64 ./cmd/defendsec-agentd "defendsec-agentd-linux-arm64"

# The evidence verifier is built for the platforms an auditor is likely to be
# on, not just the server's. It needs no server, database, network or
# credential, so shipping it widely is what makes independent verification a
# real option rather than a claim.
build linux amd64 ./cmd/defendsec-web "defendsec-web-linux-amd64"
build linux arm64 ./cmd/defendsec-web "defendsec-web-linux-arm64"

build linux   amd64 ./cmd/defendsec-verify "defendsec-verify-linux-amd64"
build linux   arm64 ./cmd/defendsec-verify "defendsec-verify-linux-arm64"
build darwin  amd64 ./cmd/defendsec-verify "defendsec-verify-darwin-amd64"
build darwin  arm64 ./cmd/defendsec-verify "defendsec-verify-darwin-arm64"
build windows amd64 ./cmd/defendsec-verify "defendsec-verify-windows-amd64.exe"

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
printf '%s\n' "$release_version" >"${OUT}/VERSION"

(
  cd "$OUT"
  sha256sum defendsec-* install-agent.sh update-server.sh VERSION >SHA256SUMS
)

# SBOMs, generated from the built binaries and appended to SHA256SUMS
# (roadmap 5.7). Required, not optional: "we publish SBOMs" is a claim that
# has to hold on every release, so a missing tool fails the build here rather
# than producing a release that quietly lacks them.
"${ROOT}/scripts/build-sboms.sh"

echo
echo "Artifacts in ${OUT}:"
ls -la "$OUT"
echo
echo "Attach every file in ${OUT} to a GitHub Release."

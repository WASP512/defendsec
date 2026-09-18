#!/usr/bin/env bash
# Verify that DefendSec's release binaries build reproducibly (roadmap 5.7).
#
# A tool that asks operators to verify signatures and provenance should be able
# to prove its own binaries are reproducible rather than assert it. This builds
# each release target twice, the second time from a copy of the tree at a
# different path with no .git directory, and fails if any hash differs.
#
# The second tree is not arbitrary. It is what somebody verifying from a
# released source tarball actually has, and it is where reproducibility breaks
# if it is going to: Go stamps the git commit into a main package by default,
# which makes the binary depend on a .git directory being present. Building
# twice in the same checkout would pass while the interesting case failed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Targets are the release binaries, one per architecture rather than all of
# them: reproducibility is a property of the build, and checking every
# GOOS/GOARCH pair costs minutes to tell us the same thing.
TARGETS=(
  "./cmd/defendsec-apid linux amd64"
  "./cmd/defendsec-agentd linux amd64"
  "./cmd/defendsec-verify linux amd64"
  "./cmd/defendsec-web linux amd64"
  "./cmd/defendsec-verify darwin arm64"
)

# The same flags scripts/build-release.sh uses. Kept in step by
# TestReproducibleFlagsMatchTheReleaseScript, so a change to one that is not
# mirrored in the other fails a test rather than silently making this check
# verify something the release does not do.
COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
LDFLAGS="-s -w -X main.buildCommit=${COMMIT}"

build_into() {
  local tree="$1" out="$2" pkg="$3" os="$4" arch="$5"
  (
    cd "$tree"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
      go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$out" "$pkg"
  )
}

echo "Preparing a second tree with no .git, at a different path"
SECOND="$WORK/verifier-tarball"
mkdir -p "$SECOND"
# Copied rather than cloned, so the second tree genuinely has no VCS metadata.
tar -C "$ROOT" \
  --exclude=.git --exclude=node_modules --exclude=dist --exclude=.next \
  -cf - . | tar -C "$SECOND" -xf -

failures=0
for target in "${TARGETS[@]}"; do
  read -r pkg os arch <<<"$target"
  name="$(basename "$pkg")-$os-$arch"
  echo "Checking ${name}"

  build_into "$ROOT"   "$WORK/a-$name" "$pkg" "$os" "$arch"
  build_into "$SECOND" "$WORK/b-$name" "$pkg" "$os" "$arch"

  a="$(sha256sum "$WORK/a-$name" | cut -d' ' -f1)"
  b="$(sha256sum "$WORK/b-$name" | cut -d' ' -f1)"
  if [[ "$a" == "$b" ]]; then
    echo "  reproducible: $a"
  else
    echo "  NOT REPRODUCIBLE"
    echo "    in-tree:          $a"
    echo "    tarball-like copy: $b"
    failures=$((failures + 1))
  fi
done

echo
if (( failures > 0 )); then
  echo "${failures} target(s) did not build reproducibly."
  echo
  echo "The usual causes, in order of likelihood:"
  echo "  - -buildvcs=false was dropped, so Go stamped VCS state into the binary"
  echo "  - -trimpath was dropped, so the build directory is embedded"
  echo "  - CGO_ENABLED=0 was dropped, so the host toolchain is involved"
  echo "  - something in the build reads the clock, the hostname or the environment"
  exit 1
fi

echo "All targets build reproducibly from a different path with no .git."
echo "Commit stamped: ${COMMIT}"

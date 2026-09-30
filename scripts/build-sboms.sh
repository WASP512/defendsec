#!/usr/bin/env bash
# Generate SBOMs for DefendSec's release artifacts (roadmap 5.7).
#
# The Go SBOMs are generated from the built binaries rather than from the
# source tree, which is the more honest source: it describes what is actually
# inside the artifact somebody downloaded, including the exact module versions
# the linker chose, rather than what `go.mod` would resolve to on a different
# day. A source-tree SBOM and a binary can disagree; only one of them is what
# the operator is running.
#
# The console's SBOM comes from `npm sbom`, which is built into npm and needs
# no extra tooling.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="${OUT:-$ROOT/dist}"

# SBOMs go beside the binaries rather than in a subdirectory.
#
# A GitHub release is a flat list of files: there is no way to publish
# dist/sbom/x.cdx.json and have somebody download it into a subdirectory. A
# nested path recorded in SHA256SUMS could therefore never be verified after
# download — the checksum check would fail on every release for a reason that
# has nothing to do with integrity. Flat here means flat there means
# verifiable there.
SBOM_DIR="$DIST"

if [[ ! -d "$DIST" ]]; then
  echo "error: $DIST does not exist. Run scripts/build-release.sh first." >&2
  exit 1
fi
mkdir -p "$SBOM_DIR"

if ! command -v cyclonedx-gomod >/dev/null 2>&1; then
  # Required rather than skipped. A release that quietly ships without an SBOM
  # because a tool was missing is exactly the sort of gap this phase exists to
  # close, and "we publish SBOMs" is a claim that has to be true every time.
  cat >&2 <<'MSG'
error: cyclonedx-gomod is not installed, and a release must not ship without SBOMs.

  go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

MSG
  exit 1
fi

echo "Generating Go SBOMs from the built binaries"
shopt -s nullglob
for binary in "$DIST"/defendsec-*; do
  # Skip anything that is not an executable artifact.
  case "$(basename "$binary")" in
    # Not executables: archives, the SBOMs from a previous run in the same
    # directory, signatures and certificates.
    *.tar.gz|*.json|*.sig|*.pem) continue ;;
  esac
  [[ -f "$binary" ]] || continue

  name="$(basename "$binary")"
  echo "  -> ${name}.cdx.json"
  # The VCS warning is expected: release builds switch off Go's automatic VCS
  # stamping so they are reproducible from a source tarball, and the commit is
  # stamped explicitly into main.buildCommit instead.
  cyclonedx-gomod bin -json -output "$SBOM_DIR/${name}.cdx.json" "$binary" 2>/dev/null
done

echo "Generating the console SBOM"
echo "  -> defendsec-console.cdx.json"
npm sbom --sbom-format cyclonedx >"$SBOM_DIR/defendsec-console.cdx.json"

# The SBOMs are themselves release artifacts, so they belong in SHA256SUMS. A
# published SBOM nobody can check the integrity of is a document, not
# evidence.
echo "Recording SBOM checksums"
(
  cd "$DIST"
  sha256sum ./*.cdx.json | sed 's|\./||' >>SHA256SUMS
  # Re-sorted so the file has one stable order regardless of the sequence the
  # build steps appended in — a checksum manifest that reorders between builds
  # is a diff nobody can read.
  sort -k2 SHA256SUMS -o SHA256SUMS
)

echo
echo "SBOMs in ${SBOM_DIR}:"
ls -la "$SBOM_DIR"/*.cdx.json

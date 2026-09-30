#!/usr/bin/env bash
# Verify a downloaded DefendSec release (roadmap 5.7).
#
# This is written for somebody who did not build the release and does not
# trust the person who did. It checks, in increasing order of what it proves:
#
#   1. checksums   — the files match the manifest they shipped with.
#   2. signature   — the manifest was signed by DefendSec's release workflow,
#                    verified against a Sigstore identity rather than a key
#                    somebody has to obtain out of band.
#   3. provenance  — GitHub attests which workflow, at which commit, built
#                    these exact bytes.
#   4. reproduce   — optionally rebuild from source and compare hashes, which
#                    is the only check that does not require trusting us at
#                    all.
#
# Checks 2-4 need tooling the operator may not have, and each is skipped with
# a clear statement of what went unverified rather than silently passing. A
# verification script that reports success for checks it did not run is worse
# than none.
set -euo pipefail

usage() {
  cat <<'MSG'
usage: verify-release.sh [--repo OWNER/REPO] [--tag TAG] [--reproduce] DIR

  DIR           directory containing the downloaded release artifacts,
                including SHA256SUMS.
  --repo        GitHub repository the release came from, for signature and
                provenance identity. Default: WASP512/defendsec.
  --tag         release tag, used when rebuilding for --reproduce.
  --reproduce   also rebuild the Go binaries from source and compare.

Exits non-zero if any check that ran failed.
MSG
}

REPO="WASP512/defendsec"
TAG=""
REPRODUCE=0
DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --reproduce) REPRODUCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) DIR="$1"; shift ;;
  esac
done

if [[ -z "$DIR" || ! -d "$DIR" ]]; then
  usage
  exit 2
fi
DIR="$(cd "$DIR" && pwd)"

skipped=()
failed=0

echo "Verifying the DefendSec release in ${DIR}"
echo

# ---------------------------------------------------------------- checksums
echo "1. Checksums"
if [[ ! -f "$DIR/SHA256SUMS" ]]; then
  echo "   FAILED: no SHA256SUMS in ${DIR}"
  failed=$((failed + 1))
else
  if (cd "$DIR" && sha256sum --quiet --check SHA256SUMS); then
    echo "   OK: every file in the manifest matches"
  else
    echo "   FAILED: at least one file does not match SHA256SUMS"
    failed=$((failed + 1))
  fi

  # "Every file matches the manifest" is not "every file is covered by the
  # manifest". sha256sum --check only looks at what it was given, so an
  # artifact absent from SHA256SUMS passes verification untouched — which is
  # the shape an attacker would want: add a file, or drop a line, and the
  # check still reports success. So the directory is compared against the
  # manifest in both directions.
  unlisted=0
  while IFS= read -r file; do
    rel="${file#./}"
    case "$rel" in
      SHA256SUMS|SHA256SUMS.sig|SHA256SUMS.pem) continue ;;
    esac
    if ! grep -qF "  $rel" "$DIR/SHA256SUMS"; then
      echo "   FAILED: ${rel} is present but not listed in SHA256SUMS"
      unlisted=$((unlisted + 1))
    fi
  done < <(cd "$DIR" && find . -type f | sort)
  if (( unlisted == 0 )); then
    echo "   OK: no unlisted files"
  else
    failed=$((failed + unlisted))
  fi
fi
echo

# ---------------------------------------------------------------- signature
echo "2. Signature over SHA256SUMS"
if ! command -v cosign >/dev/null 2>&1; then
  echo "   SKIPPED: cosign is not installed (https://docs.sigstore.dev/cosign/installation/)"
  skipped+=("signature")
elif [[ ! -f "$DIR/SHA256SUMS.sig" || ! -f "$DIR/SHA256SUMS.pem" ]]; then
  echo "   SKIPPED: SHA256SUMS.sig or SHA256SUMS.pem is missing from the download"
  skipped+=("signature")
else
  # Keyless verification. The identity is the release workflow itself, so
  # there is no long-lived key for anybody to lose or for an attacker to
  # steal — and nothing for the operator to fetch from a second channel they
  # would have to trust separately.
  if cosign verify-blob \
      --certificate "$DIR/SHA256SUMS.pem" \
      --signature "$DIR/SHA256SUMS.sig" \
      --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$DIR/SHA256SUMS" >/dev/null 2>&1; then
    echo "   OK: signed by ${REPO}'s release workflow"
  else
    echo "   FAILED: the signature does not verify against ${REPO}'s release workflow"
    echo "           Run the cosign command from this script by hand to see why."
    failed=$((failed + 1))
  fi
fi
echo

# --------------------------------------------------------------- provenance
echo "3. Build provenance"
if ! command -v gh >/dev/null 2>&1; then
  echo "   SKIPPED: the gh CLI is not installed"
  skipped+=("provenance")
else
  # One artifact is enough to establish which workflow and commit produced
  # the release, and the checksum manifest already binds the rest to it.
  target="$DIR/SHA256SUMS"
  if gh attestation verify "$target" --repo "$REPO" >/dev/null 2>&1; then
    echo "   OK: GitHub attests which workflow and commit built this"
  else
    echo "   FAILED: no verifiable provenance attestation for SHA256SUMS"
    failed=$((failed + 1))
  fi
fi
echo

# --------------------------------------------------------------- reproduce
echo "4. Reproducible rebuild"
if (( REPRODUCE == 0 )); then
  echo "   SKIPPED: pass --reproduce to rebuild from source and compare"
  echo "            This is the only check that does not require trusting us."
  skipped+=("reproducible rebuild")
elif ! command -v go >/dev/null 2>&1; then
  echo "   SKIPPED: Go is not installed, so nothing can be rebuilt"
  skipped+=("reproducible rebuild")
elif [[ -z "$TAG" ]]; then
  echo "   SKIPPED: --reproduce needs --tag to know which source to build"
  skipped+=("reproducible rebuild")
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  echo "   Fetching ${REPO} at ${TAG}"
  if ! git clone --depth 1 --branch "$TAG" "https://github.com/${REPO}.git" "$work/src" >/dev/null 2>&1; then
    echo "   SKIPPED: could not clone ${REPO} at ${TAG}"
    skipped+=("reproducible rebuild")
  else
    commit="$(git -C "$work/src" rev-parse HEAD)"
    # The .git directory is removed on purpose. Release builds switch off Go's
    # automatic VCS stamping precisely so that its presence or absence cannot
    # change the output; removing it here proves that rather than assuming it.
    rm -rf "$work/src/.git"
    mismatches=0
    checked=0
    for pkg in defendsec-apid defendsec-agentd defendsec-verify defendsec-web; do
      for pair in "linux amd64" "linux arm64"; do
        read -r os arch <<<"$pair"
        artifact="$DIR/${pkg}-${os}-${arch}"
        [[ -f "$artifact" ]] || continue
        checked=$((checked + 1))
        ldflags="-s -w -X main.buildCommit=${commit}"
        if [[ "$pkg" == "defendsec-agentd" ]]; then
          version="${TAG#v}"
          ldflags="${ldflags} -X main.agentVersion=${version}"
        fi
        (
          cd "$work/src"
          GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
            go build -trimpath -buildvcs=false -ldflags "$ldflags" \
              -o "$work/${pkg}-${os}-${arch}" "./cmd/${pkg}"
        )
        a="$(sha256sum "$artifact" | cut -d' ' -f1)"
        b="$(sha256sum "$work/${pkg}-${os}-${arch}" | cut -d' ' -f1)"
        if [[ "$a" == "$b" ]]; then
          echo "   OK: ${pkg}-${os}-${arch}"
        else
          echo "   FAILED: ${pkg}-${os}-${arch} does not match what we rebuilt"
          echo "           downloaded: $a"
          echo "           rebuilt:    $b"
          mismatches=$((mismatches + 1))
        fi
      done
    done
    if (( checked == 0 )); then
      echo "   SKIPPED: no Go binaries found in ${DIR} to compare"
      skipped+=("reproducible rebuild")
    elif (( mismatches > 0 )); then
      failed=$((failed + mismatches))
    fi
  fi
fi
echo

# ------------------------------------------------------------------ summary
echo "-------------------------------------------------------------"
if (( ${#skipped[@]} > 0 )); then
  echo "Not verified: ${skipped[*]}"
fi
if (( failed > 0 )); then
  echo "RESULT: ${failed} check(s) FAILED. Do not deploy these artifacts."
  exit 1
fi
if (( ${#skipped[@]} > 0 )); then
  echo "RESULT: every check that ran passed, but the above were not verified."
  exit 0
fi
echo "RESULT: all checks passed."

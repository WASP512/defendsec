#!/usr/bin/env bash
# Build the DefendSec agent MSI from a Windows agent binary, on Linux, with
# wixl (msitools). Usage: build-msi.sh AGENT_EXE OUT_MSI VERSION
#
# The MSI is not byte-reproducible: Windows Installer requires a fresh
# package code per build. The binary inside it is, and can be checked by
# extracting it (msiextract OUT_MSI) and comparing it to the release's
# defendsec-agentd-windows-amd64.exe, which check-reproducible.sh covers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exe="$1" out="$2" version="$3"

# MSI versions are major.minor.build with numeric parts; a tag like
# 1.4.0-rc1 or a describe string maps to its numeric prefix, and anything
# else to 0.0.0 so development builds still produce an installable package.
msi_version="$(sed -E 's/^v//; s/^([0-9]+(\.[0-9]+){0,2}).*/\1/' <<<"$version")"
[[ "$msi_version" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || msi_version="0.0.0"

echo "  -> $(basename "$out") (MSI version ${msi_version})"
wixl -a x64 \
  -D "Version=${msi_version}" \
  -D "AgentExe=${exe}" \
  -D "UninstallPs1=${ROOT}/packaging/agent/uninstall-agent.ps1" \
  -o "$out" "${ROOT}/packaging/windows/defendsec-agent.wxs" 2> >(grep -v 'GLib-GObject' >&2)

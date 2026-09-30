#!/bin/bash
# Build an installer package for the macOS agent. Runs on macOS only
# (pkgbuild). Usage:
#   scripts/build-macos-pkg.sh AGENT_BINARY VERSION OUT.pkg [--sign "Developer ID Installer: ..."]
# See docs/MACOS.md.
set -euo pipefail
[[ "$(uname -s)" == "Darwin" ]] || { echo "pkgbuild exists only on macOS" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bin="$1" version="$2" out="$3"; shift 3
sign=()
if [[ "${1:-}" == "--sign" ]]; then sign=(--sign "$2"); fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
install -d "$work/root/usr/local/bin" "$work/scripts"
install -m 0755 "$bin" "$work/root/usr/local/bin/defendsec-agentd"
install -m 0755 "$ROOT/packaging/agent/uninstall-agent-macos.sh" "$work/root/usr/local/bin/defendsec-agent-uninstall"
install -m 0755 "$ROOT/packaging/agent/install-agent-macos.sh" "$work/scripts/install-agent-macos.sh"

cat >"$work/scripts/postinstall" <<'POST'
#!/bin/bash
# Enroll when the MDM has deployed agent.conf; otherwise leave the binary in
# place for install-agent-macos.sh to configure.
set -euo pipefail
conf="/Library/Application Support/DefendSec/agent.conf"
[[ -f "$conf" ]] || { echo "DefendSec: no $conf; agent installed but not enrolled"; exit 0; }
# shellcheck disable=SC1090
. "$conf"
exec /bin/bash "$(dirname "$0")/install-agent-macos.sh" --binary /usr/local/bin/defendsec-agentd \
  --server-http "$SERVER_HTTP" --server-grpc "$SERVER_GRPC" \
  --tls-server-name "$TLS_SERVER_NAME" --enroll-secret "$ENROLL_SECRET"
POST
chmod 0755 "$work/scripts/postinstall"

pkgbuild --root "$work/root" --scripts "$work/scripts" \
  --identifier com.defendsec.agent --version "${version#v}" \
  --install-location / "${sign[@]}" "$out"
echo "Built $out"

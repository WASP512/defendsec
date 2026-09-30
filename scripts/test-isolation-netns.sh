#!/usr/bin/env bash
# Exercise Linux host isolation against real traffic (roadmap: isolation).
#
# Builds two network namespaces joined by a point-to-point link, with IPv4
# and IPv6:
#   agent — where the isolation test runs
#   peer  — serves the "control plane" on 47263 and an unrelated service on
#           8080, and keeps connecting back to agent:9000
# then runs TestIsolationWithRealTraffic inside "agent" for both the nftables
# and iptables backends. Needs root, ip, nft, iptables and ip6tables. Touches
# nothing outside the two namespaces it creates.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

A=ds-iso-agent P=ds-iso-peer
ip netns del "$A" 2>/dev/null || true   # left over from an interrupted run
ip netns del "$P" 2>/dev/null || true
WORK="$(mktemp -d)"
cleanup() {
  [[ -n "${PEER_PIDS:-}" ]] && kill $PEER_PIDS 2>/dev/null || true
  ip netns del "$A" 2>/dev/null || true
  ip netns del "$P" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ip netns add "$A"
ip netns add "$P"
for ns in "$A" "$P"; do ip -n "$ns" link set lo up; done
ip -n "$A" tuntap add dev ds-tun-a mode tun
ip -n "$P" tuntap add dev ds-tun-p mode tun

cat >"$WORK/relay.py" <<'PY'
import ctypes, fcntl, os, select, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNET, TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x40000000, 0x400454CA, 0x0001, 0x1000
def tun_in(ns, name):
    fd = os.open("/run/netns/" + ns, os.O_RDONLY)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "setns " + ns)
    os.close(fd)
    t = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(t, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return t
a = tun_in(sys.argv[1], sys.argv[2])
p = tun_in(sys.argv[3], sys.argv[4])
peer = {a: p, p: a}
while True:
    for fd in select.select([a, p], [], [])[0]:
        os.write(peer[fd], os.read(fd, 65535))
PY
python3 "$WORK/relay.py" "$A" ds-tun-a "$P" ds-tun-p &
PEER_PIDS=$!
sleep 0.5
ip -n "$A" link set ds-tun-a up
ip -n "$P" link set ds-tun-p up
ip -n "$A" addr add 10.77.0.1 peer 10.77.0.2 dev ds-tun-a
ip -n "$P" addr add 10.77.0.2 peer 10.77.0.1 dev ds-tun-p
PEER6=""
if [[ -d /proc/sys/net/ipv6 ]]; then
  ip -n "$A" -6 addr add fd77::1/64 dev ds-tun-a nodad
  ip -n "$P" -6 addr add fd77::2/64 dev ds-tun-p nodad
  PEER6="fd77::2"
else
  echo "NOTE: this kernel has no IPv6; only IPv4 traffic is exercised." >&2
fi

cat >"$WORK/peer.py" <<'PY'
import socket, threading, time, sys
def serve(fam, host, port):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((host, port)); s.listen(64)
    while True:
        c, _ = s.accept()
        def echo(c):
            try:
                while True:
                    d = c.recv(4096)
                    if not d: break
                    c.sendall(b"pong\n")
            except OSError:
                pass
            c.close()
        threading.Thread(target=echo, args=(c,), daemon=True).start()
hosts = [(socket.AF_INET, "10.77.0.2")] + ([(socket.AF_INET6, "fd77::2")] if socket.has_ipv6 and len(sys.argv) > 1 else [])
for fam, host in hosts:
    for port in (47263, 8080):
        threading.Thread(target=serve, args=(fam, host, port), daemon=True).start()
def probe():
    while True:
        try:
            socket.create_connection(("10.77.0.1", 9000), timeout=0.3).close()
        except OSError:
            pass
        time.sleep(0.1)
threading.Thread(target=probe, daemon=True).start()
while True: time.sleep(3600)
PY
ip netns exec "$P" python3 "$WORK/peer.py" $PEER6 &
PEER_PIDS="$PEER_PIDS $!"
sleep 1

# A stand-in for the host's own firewall (firewalld, ufw), loaded before any
# connection opens. It turns connection tracking on, as a real firewall does,
# so a session open before isolation is tracked as established — the case
# isolation must still cut. And it accepts everything, so the test also shows
# that isolation holds alongside another firewall's accept rules.
ip netns exec "$A" nft -f - <<'NFT'
table inet hostfw {
	chain output { type filter hook output priority 0; policy accept; ct state established,related accept; }
	chain input { type filter hook input priority 0; policy accept; ct state established,related accept; }
}
NFT

(cd "$ROOT" && go test -c -o "$WORK/agentcmd.test" ./internal/agentcmd)
ip netns exec "$A" env DEFENDSEC_NETNS_PEER4=10.77.0.2 DEFENDSEC_NETNS_PEER6="$PEER6" \
  "$WORK/agentcmd.test" -test.run TestIsolationWithRealTraffic -test.v -test.count=1

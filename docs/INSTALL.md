# Install DefendSec (server + agent)

Two separate installers:

1. **Server** — Proxmox VE helper (creates an LXC) or `install-server.sh` on a Linux VM
2. **Agent** — separate download/install on each host you want to inventory

Repo default: [`WASP512/defendsec`](https://github.com/WASP512/defendsec) (private). Pass a GitHub PAT when cloning:

```bash
export GH_TOKEN=github_pat_...   # Contents: read
CTID=210 bash packaging/proxmox/ct/defendsec.sh
# or
sudo GH_TOKEN=... bash packaging/proxmox/install-server.sh
```

## 1) Proxmox VE — create the server CT

Run on the **Proxmox host** as root:

```bash
export GH_TOKEN=github_pat_...   # needed while the GitHub repo is private
bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
```

If `curl` of the raw script fails (private repo), copy `packaging/proxmox/` onto the Proxmox host from a checkout and run `bash packaging/proxmox/ct/defendsec.sh` locally.
Optional knobs:

| Env | Default | Purpose |
| --- | --- | --- |
| `CTID` | next free ≥200 | Container ID |
| `HOSTNAME` | `defendsec` | CT hostname (+ TLS SAN) |
| `STORAGE` | auto | Proxmox storage |
| `BRIDGE` | `vmbr0` | Network bridge |
| `CORES` / `MEMORY` / `DISK` | `2` / `2048` / `16` | Resources |
| `REPO_URL` / `REPO_REF` | this repo / `main` | Source to build |

The script creates a Debian 12 LXC (nesting enabled for Docker Postgres), then runs `packaging/proxmox/install-server.sh` inside it.

When it finishes you get:

- Console on `http://<ct-ip>:47261`
- Enroll HTTPS on `https://<ct-ip>:47262`
- mTLS gRPC on `<ct-ip>:47263`
- Admin token + enroll secret
- Agent download bundle served from `http://<ct-ip>:47261/downloads/…`

Enter the CT anytime with `pct enter <CTID>`.

### Server-only (no Proxmox)

On a Debian/Ubuntu (or Fedora) VM as root:

```bash
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/install-server.sh | bash
```

Same layout: `/opt/defendsec` source, `/var/lib/defendsec` data, systemd units `defendsec-apid` + `defendsec-console`.

## 2) Agent — separate download per host

Do **not** re-run the Proxmox/server script on endpoints. On each Linux host:

```bash
curl -fsSL "http://SERVER:47261/downloads/install-agent.sh" | sudo bash -s -- \
  --server-http "https://SERVER:47262" \
  --server-grpc "SERVER:47263" \
  --tls-server-name "SERVER" \
  --enroll-secret "YOUR_ENROLL_SECRET" \
  --download-base "http://SERVER:47261/downloads"
```

Replace `SERVER` with the CT hostname or IP (must match a TLS SAN from install). Copy the exact one-liner from the Enroll page after sign-in.

What the agent installer does:

- Downloads `defendsec-agentd-linux-<arch>` from your server’s `/downloads` (or GitHub Releases if `--download-base` is omitted and a release exists)
- Installs `/usr/local/bin/defendsec-agentd`
- Writes `/etc/defendsec/enroll-secret` + `agentd.env`
- Enables `defendsec-agentd.service`

Offline:

```bash
sudo bash install-agent.sh \
  --binary ./defendsec-agentd-linux-amd64 \
  --server-http https://SERVER:47262 \
  --server-grpc SERVER:47263 \
  --tls-server-name SERVER \
  --enroll-secret SECRET
```

## Ports

| Port | Service |
| --- | --- |
| `47261` | Console + agent download HTTP |
| `47262` | Apid HTTPS enroll / CA |
| `47263` | mTLS gRPC |
| `47264` | Admin API (loopback only) |
| `5432` | Postgres (loopback only) |

Open `47261–47263` from your admin network / agents. Keep `47264` and Postgres on localhost.

## Publishing agent binaries (maintainers)

```bash
./scripts/build-release.sh
# artifacts in dist/:
#   defendsec-apid-linux-amd64
#   defendsec-agentd-linux-amd64
#   defendsec-agentd-linux-arm64
#   SHA256SUMS
```

Server install already copies the matching agent binary + `install-agent.sh` into `/var/lib/defendsec/downloads`. Attach the `dist/` agent binaries to a GitHub Release if you want public curl-from-GitHub installs.

## Troubleshooting

- **Agent TLS verify failed** — `--tls-server-name` must match a SAN on the apid cert (`DEFENDSEC_TLS_HOSTNAME` / wipe `/var/lib/defendsec/pki` once and restart `defendsec-apid`).
- **Downloads 404** — confirm `DEFENDSEC_DOWNLOADS_DIR` and that files exist under `/var/lib/defendsec/downloads`.
- **LXC + Docker** — CT needs `features nesting=1` (set by the Proxmox script).
- **Logs** — `journalctl -u defendsec-apid -u defendsec-console -u defendsec-agentd -f`

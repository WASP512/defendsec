# Install DefendSec (server + agent)

Two separate installers:

1. **Server** — Proxmox VE helper (creates an LXC) or `install-server.sh` on a Linux VM
2. **Agent** — separate download/install on each host you want to inventory

Repo default: [`WASP512/defendsec`](https://github.com/WASP512/defendsec) (public). Clone and curl work without a token. Optional `GH_TOKEN` is only for private forks or GitHub API rate limits.

## 1) Proxmox VE — create the server CT

Run on the **Proxmox host** as root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
```

If you already have a checkout on the Proxmox host, run `bash packaging/proxmox/ct/defendsec.sh` from it instead.

Optional knobs:

| Env | Default | Purpose |
| --- | --- | --- |
| `CTID` | next free ≥200 | Container ID |
| `CT_HOSTNAME` | `defendsec` | CT hostname (+ TLS SAN) |
| `STORAGE` | auto (`rootdir`/`images`) | CT disk storage (often `local-lvm`) |
| `TEMPLATE_STORAGE` | auto (`vztmpl`) | LXC template storage for `pveam` (usually `local`) |
| `BRIDGE` | `vmbr0` | Network bridge |
| `CORES` / `MEMORY` / `DISK` | `2` / `2048` / `16` | Resources |
| `REPO_URL` / `REPO_REF` | this repo / `main` | Source to build |
| `GH_TOKEN` | unset | Optional; not required for the public repo |

Do **not** point `pveam download` at LVM-thin. Templates need directory storage with content type `vztmpl` (`TEMPLATE_STORAGE`, typically `local`). The CT rootfs uses `STORAGE`, which must support `rootdir` (typically `local-lvm`). Auto-detect reads content types from `pvesm config` and fails fast with the storage name if the choice cannot hold that content. Override when it picks wrong:

```bash
TEMPLATE_STORAGE=local STORAGE=local-lvm CTID=210 bash packaging/proxmox/ct/defendsec.sh
```

Use `CT_HOSTNAME`, not `HOSTNAME`, to name the container. Bash always sets `HOSTNAME` to the Proxmox host's own name, so the script ignores an inherited value that matches the host:

```bash
CT_HOSTNAME=defendsec CTID=210 bash packaging/proxmox/ct/defendsec.sh
```

The script creates a Debian 12 LXC, then runs `packaging/proxmox/install-server.sh` inside it.

Postgres uses **native packages** by default (no Docker). That avoids Docker-in-LXC failures on Proxmox. Optional: `--postgres docker` on `install-server.sh` if you really want containers.

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

Same layout: `/opt/defendsec` source, `/var/lib/defendsec` data, systemd units `defendsec-apid` + `defendsec-console`. Postgres is native by default.

### Re-run after a failed CT install

If the first run left a half-installed CT, destroy it on the Proxmox host, then re-run `ct/defendsec.sh`:

```bash
pct stop <CTID>
pct destroy <CTID>
```

Typical failure: `pveam download` against disk storage (`local-lvm`) instead of template storage. Re-run with `TEMPLATE_STORAGE=local`.

Or enter the CT and re-run only the server installer:

```bash
pct enter <CTID>
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/install-server.sh | bash
```

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

## Uninstall

### Proxmox CT (control plane)

On the **Proxmox host**:

```bash
pct stop <CTID>
pct destroy <CTID>
```

That removes the whole server VM (apid, console, native Postgres data inside the CT).

### Server on a Linux VM (no Proxmox)

Inside the host that ran `install-server.sh`:

```bash
sudo bash packaging/proxmox/uninstall-server.sh
# also delete data + source tree:
sudo bash packaging/proxmox/uninstall-server.sh --purge-data
# also drop the native Postgres database/role named defendsec:
sudo bash packaging/proxmox/uninstall-server.sh --purge-data --purge-postgres
```

`--purge-postgres` does not uninstall the PostgreSQL packages.

### Agent

On each enrolled host:

```bash
sudo bash packaging/agent/uninstall.sh
sudo bash packaging/agent/uninstall.sh --purge-data
```

`--purge-data` removes `/var/lib/defendsec-agent`. Agent uninstall leaves a control-plane `/etc/defendsec` tree alone (it only deletes `enroll-secret` and `agentd.env`).

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

# Install DefendSec

This is the first-time install guide. Follow it in order.

You install **two different things**:

1. **Server** — the console, API, and database. Install this once.
2. **Agent** — a small program on each machine you want to inventory. Install this separately on every host.

The repository is public: [github.com/WASP512/defendsec](https://github.com/WASP512/defendsec). You do **not** need a GitHub token.

---

## Pick an install path

| Your setup | What to run |
| --- | --- |
| You have a **Proxmox VE** host | [Path A](#path-a--proxmox-creates-the-server-container) (recommended) |
| You have a **Debian/Ubuntu/Fedora VM** and no Proxmox | [Path B](#path-b--linux-vm-no-proxmox) |
| You already have a half-broken container | [Start over](#start-over-after-a-failed-install) |

Then go to [First login](#first-login) and [Enroll hosts](#enroll-hosts).

---

## Path A — Proxmox creates the server container

Run this **on the Proxmox VE host**, as **root**. It creates a Debian 12 LXC, installs Postgres, builds the server, and starts the services.

```bash
echo "Downloading DefendSec installer…" && \
  curl -fL --progress-bar \
    https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh \
    -o /tmp/defendsec.sh && \
  bash /tmp/defendsec.sh
```

**How long?** Often **15–30 minutes** on first run. Most of that is downloading a Debian template and compiling Go/Node inside the container. Later reinstalls are faster if the template is already cached.

When it finishes, you should see something like:

```text
Container:  200 (defendsec)
Root pass:  <printed once — not stored>
Console:    http://192.168.1.50:47261
Enroll TLS: https://192.168.1.50:47262
gRPC:       192.168.1.50:47263

Admin token: pct exec 200 -- cat /var/lib/defendsec/admin-token.txt
```

Write down the **CTID** (here `200`) and the **console URL**. The admin token is **not** printed; retrieve it in the next section.

### Optional settings (only if auto-detect is wrong)

Prefix the same command with environment variables. Common ones:

```bash
CTID=210 \
CT_HOSTNAME=defendsec \
TEMPLATE_STORAGE=local \
STORAGE=local-lvm \
BRIDGE=vmbr0 \
bash /tmp/defendsec.sh
```

Download `/tmp/defendsec.sh` first with the visible download command from Path A.

| Setting | Default | When to set it |
| --- | --- | --- |
| `CTID` | next free ID ≥ 200 | You want a specific container ID |
| `CT_HOSTNAME` | `defendsec` | TLS certificate name / hostname inside the CT |
| `STORAGE` | first storage that can hold CT disks (`rootdir`, often `local-lvm`) | Auto-detect picked the wrong disk storage |
| `TEMPLATE_STORAGE` | first storage that can hold LXC templates (`vztmpl`, usually `local`) | `pveam download` failed against LVM-thin |
| `BRIDGE` | `vmbr0` | Your LAN bridge is not `vmbr0` |
| `CORES` / `MEMORY` / `DISK` | `2` / `4096` / `24` | First source build needs about 4 GB RAM and 24 GB disk |
| `REPO_REF` | `main` | Install a branch other than `main` |

Use **`CT_HOSTNAME`**, not `HOSTNAME`. Bash already sets `HOSTNAME` to the Proxmox host’s own name.

Templates **must** live on directory storage with content type `vztmpl` (usually `local`). The container disk **must** live on storage with content type `rootdir` (usually `local-lvm`). Do not point template download at LVM-thin.

---

## Path B — Linux VM (no Proxmox)

On a Debian, Ubuntu, or Fedora machine as **root**:

```bash
echo "Downloading DefendSec server installer…" && \
  curl -fL --progress-bar \
    https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/install-server.sh \
    -o /tmp/defendsec-install-server.sh && \
  bash /tmp/defendsec-install-server.sh
```

That installs:

- source in `/opt/defendsec`
- data in `/var/lib/defendsec`
- systemd units `defendsec-apid` and `defendsec-console`
- native Postgres (not Docker)

Re-running this script **keeps** the existing Postgres password, admin token, viewer token, and enroll secret unless you pass replacements.
It also installs the one-click update helper. After that bootstrap, future
stable releases can be installed from **Operations → Updates** without SSH,
Git, Go, Node, or an on-server source build.

Useful flags:

```bash
bash install-server.sh --help
# --advertise-hostname NAME   TLS name the agents will verify
# --admin-token TOKEN         set / replace the console token
# --viewer-token TOKEN        enable a read-only login
# --pg-password PASSWORD      set / replace the database password
# --postgres native|docker    default is native
```

---

## First login

1. Open **`http://<server-ip>:47261`**. Type **http**. Port `47261` is not HTTPS. Using `https://…:47261` produces `SSL_ERROR_RX_RECORD_TOO_LONG`.
2. There is **no username**. Paste the admin token.
3. Get the token from the Proxmox host (replace `200` with your CTID):

   ```bash
   pct exec 200 -- cat /var/lib/defendsec/admin-token.txt
   ```

   On a non-Proxmox VM:

   ```bash
   sudo cat /var/lib/defendsec/admin-token.txt
   ```

The enroll secret (needed only if you build an agent command by hand) is:

```bash
pct exec 200 -- jq -r .enrollSecret /var/lib/defendsec/defendsec.json
```

You usually do **not** need the container root password. `pct enter 200` gives you a root shell. If you do need to reset it:

```bash
pct exec 200 -- passwd root
```

### Keep the console on a trusted network

The admin token travels over plain HTTP on port `47261`. Use a trusted LAN, or put an HTTPS reverse proxy in front. If you terminate TLS at a proxy, set both of these in `/etc/defendsec/console.env` and restart `defendsec-console`:

```bash
DEFENDSEC_COOKIE_SECURE=true
DEFENDSEC_PUBLIC_CONSOLE_URL=https://defendsec.example.com
```

---

## Enroll hosts

Do **not** run the Proxmox helper on the machines you want to inventory.

On each Linux host (amd64 or arm64):

1. Sign in to the console as admin.
2. Open **Enroll**.
3. Copy **Agent install** and run it with `sudo` on that host.

The command looks like this (the Enroll page fills in the right values):

```bash
echo "Downloading DefendSec agent installer…" && \
  curl -fL --progress-bar \
    "http://SERVER:47261/downloads/install-agent.sh" \
    -o /tmp/install-agent.sh && \
sudo bash /tmp/install-agent.sh \
  --server-http "https://SERVER:47262" \
  --server-grpc "SERVER:47263" \
  --tls-server-name "SERVER" \
  --enroll-secret "YOUR_ENROLL_SECRET" \
  --download-base "http://SERVER:47261/downloads"
```

`--tls-server-name` must match a name or IP on the server certificate (the hostname you advertised at install, often `defendsec`).

The agent installer:

- downloads `defendsec-agentd` from **your** server
- installs `/usr/local/bin/defendsec-agentd`
- writes `/etc/defendsec/enroll-secret` and `agentd.env`
- enables `defendsec-agentd.service`

Then open **Hosts**. The machine should appear within about a minute.

### After you sign in

| Page | Use it for |
| --- | --- |
| **Fleet** | Counts and a host table |
| **Hosts** | One machine: inventory, patches, integrity, signed response |
| **Enroll** | Copy the agent install command (admin only) |
| **Advisories / Alerts** | CVE matches and detections (Alerts needs Postgres, which packaged installs have) |
| **Integrity** | File-hash drift |
| **Policies** | Snapshot checks (check-in, firewall, encryption, …) |

### Offline agent install

Copy `defendsec-agentd-linux-amd64` (or `arm64`) from `/var/lib/defendsec/downloads` on the server, then:

```bash
sudo bash install-agent.sh \
  --binary ./defendsec-agentd-linux-amd64 \
  --server-http https://SERVER:47262 \
  --server-grpc SERVER:47263 \
  --tls-server-name SERVER \
  --enroll-secret SECRET
```

---

## Check that it worked

| Check | How |
| --- | --- |
| Console loads | `http://<ip>:47261/login` in a browser |
| Services up (inside the CT/VM) | `systemctl status defendsec-apid defendsec-console` |
| Host enrolled | Console → **Hosts**; status online within ~2 minutes |
| Logs | `journalctl -u defendsec-apid -u defendsec-console -u defendsec-agentd -f` |

---

## Start over after a failed install

On the **Proxmox host**, destroy the leftover container, then run Path A again:

```bash
pct stop 200
pct destroy 200
```

Replace `200` with your CTID.

If the container exists but the **server install** never finished, you can finish it without recreating the CT:

```bash
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/install-server.sh \
  -o /tmp/defendsec-install-server.sh
pct push 200 /tmp/defendsec-install-server.sh /tmp/defendsec-install-server.sh
pct exec 200 -- bash /tmp/defendsec-install-server.sh --advertise-hostname defendsec
```

---

## Uninstall

### Whole Proxmox server

On the Proxmox host this deletes the container and everything in it:

```bash
pct stop 200
pct destroy 200
```

### Server on a Linux VM

```bash
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/uninstall-server.sh | sudo bash
# also delete /var/lib/defendsec, /opt/defendsec, /etc/defendsec:
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/uninstall-server.sh | sudo bash -s -- --purge-data
# also drop the native Postgres database/role named defendsec:
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/uninstall-server.sh | sudo bash -s -- --purge-data --purge-postgres
```

`--purge-postgres` does not uninstall PostgreSQL packages.

### Agent on an enrolled host

```bash
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/agent/uninstall.sh | sudo bash
# also remove /var/lib/defendsec-agent:
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/agent/uninstall.sh | sudo bash -s -- --purge-data
```

---

## Ports

| Port | What | Who needs it |
| --- | --- | --- |
| `47261` | Console + agent downloads (HTTP) | Your browser, agent installer |
| `47262` | Enroll / CA (HTTPS) | Agents |
| `47263` | mTLS gRPC | Agents |
| `47264` | Admin API | Localhost only |
| `5432` | Postgres | Localhost only |

Open `47261–47263` from your admin network and from agents. Leave `47264` and Postgres bound to localhost.

---

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `ostemplate: value may only be 255 characters long` | Template storage mixed with disk storage, or a noisy template path | Set `TEMPLATE_STORAGE=local` and `STORAGE=local-lvm`. Current helper auto-splits these. |
| `pveam download` fails on `local-lvm` | LVM-thin cannot store LXC templates | `TEMPLATE_STORAGE=local` |
| `bash: curl: command not found` **inside** the CT | Debian 12 template has no curl | Current helper downloads on the **Proxmox host** and pushes the script in. Update to latest `main` and re-run, or use the “finish install” commands above. |
| `package log/slog is not in GOROOT` (Go 1.19) | Distro Go is too old | Current installer installs verified upstream Go/Node. Re-run `install-server.sh` from `main`. |
| Browser `SSL_ERROR_RX_RECORD_TOO_LONG` | Used `https://` on port 47261 | Use `http://<ip>:47261` |
| Cannot reach the UI | Install failed before services started, or wrong IP/port | `systemctl status defendsec-console defendsec-apid` inside the CT; confirm port 47261 |
| Agent TLS verify failed | `--tls-server-name` does not match the cert | Use the CT hostname (`defendsec` by default), or wipe `/var/lib/defendsec/pki` once and restart `defendsec-apid` so SANs refresh |
| Downloads 404 | Agent installer pointed at the wrong host | Confirm files exist in `/var/lib/defendsec/downloads` |
| Forgot the admin token | Token is on disk, not printed at the end | `pct exec <CTID> -- cat /var/lib/defendsec/admin-token.txt` |

---

## Notes for operators

- Debian 12’s packaged Go 1.19 and Node 18 are too old. The installer downloads upstream Go and Node into `/usr/local` and checks the published SHA256. Pin with `GO_VERSION=go1.24.6` / `NODE_VERSION=v22.20.0` if you need specific builds.
- Postgres is **native packages** by default so Proxmox LXC does not need Docker. Use `--postgres docker` only if you know you want it (`nesting=1` is already set on the CT).
- Sample demo hosts are **off** in production. Set `DEFENDSEC_ENABLE_SAMPLE_DATA=true` in `console.env` only if you want them.

Day-to-day backup, viewer tokens, and reverse proxy: [OPERATIONS.md](./OPERATIONS.md).

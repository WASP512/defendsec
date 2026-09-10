# DefendSec

Self-hosted inventory and host security for machines you enroll. No accounts, no cloud, no MDM.

The server stores host inventory, pending patches, file-integrity hashes, and advisory matches. You install **one server**, then a **separate agent** on each machine you want to watch.

This is not FleetDM and it is not MDM. There is no remote wipe, lock, DEP, or configuration profiles.

## Start here

Most people run the server as a Proxmox LXC. That path is two commands plus a browser login.

1. **Create the server** on the Proxmox host (as root). First install often takes **15–30 minutes** while it builds Go and Node:

   ```bash
   bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
   ```

2. **Open the console** at `http://<container-ip>:47261` (use **http**, not https). There is no username. Get the admin token from the Proxmox host:

   ```bash
   pct exec <CTID> -- cat /var/lib/defendsec/admin-token.txt
   ```

3. **Enroll each host** with the exact command on the console **Enroll** page. Do not re-run the Proxmox script on laptops or VMs you want to inventory.

Full walkthrough, Linux-VM install, uninstall, and troubleshooting: **[docs/INSTALL.md](docs/INSTALL.md)**.

Day-to-day backup, logs, viewers, and reverse proxy: **[docs/OPERATIONS.md](docs/OPERATIONS.md)**.

## What you get

- Host list with online/offline
- Software versions and pending patches
- Advisory matches you can acknowledge
- File integrity on a small set of system files
- Signed isolate / kill / live-query commands for enrolled Go agents

## What you do not get

- Live NVD/OSV sync unless you turn ingest on yourself
- Remote patch install or reboot orchestration
- Lock, wipe, DEP, configuration profiles, Windows CSP
- Enterprise FIM (inotify tuning, signed baselines)

## Other paths

| If you want… | Read |
| --- | --- |
| Production install / uninstall | [docs/INSTALL.md](docs/INSTALL.md) |
| Backup, credentials, proxy, alerts | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Fedora laptop lab (developers) | [docs/FEDORA.md](docs/FEDORA.md) |
| Product scope in the UI | `/scope` after login |
| Historical phase plan | [docs/NEXT-PHASES.md](docs/NEXT-PHASES.md) |

## Developers: run the console locally

```bash
npm install
npm run dev
```

Open [http://127.0.0.1:47261](http://127.0.0.1:47261). When `DEFENDSEC_ADMIN_TOKEN` is unset, the token is `defendsec-local-admin` (also written to `data/admin-token.txt`). Production installs create a random token instead.

The Python HTTP agent still works for inventory-only labs:

```bash
python3 agent/defendsec-agent.py --server http://YOUR_SERVER:47261 --enroll-secret SECRET
```

Prefer the packaged Go agent (`defendsec-agentd`) for mTLS, signed commands, and systemd. Copy that command from **Enroll**.

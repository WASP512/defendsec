# Proxmox VE packaging

| Script | Where to run | Purpose |
| --- | --- | --- |
| [`ct/defendsec.sh`](./ct/defendsec.sh) | Proxmox **host** | Create Debian 12 LXC + run server install |
| [`install-server.sh`](./install-server.sh) | Inside CT / any Linux VM | Install Postgres, apid, console, agent downloads |
| [`uninstall-server.sh`](./uninstall-server.sh) | Inside CT / Linux VM | Stop units; optional `--purge-data` / `--purge-postgres` |

`ct/defendsec.sh` uses `TEMPLATE_STORAGE` (vztmpl, usually `local`) for `pveam` and `STORAGE` (rootdir/images, often `local-lvm`) for the CT disk.

Agent install is **separate**: [`../agent/install.sh`](../agent/install.sh).

Full walkthrough: [`../../docs/INSTALL.md`](../../docs/INSTALL.md).

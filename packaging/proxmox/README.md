# Proxmox / server packaging

These scripts install the **server** (console + API + Postgres). They do **not** enroll laptops or VMs. Agents use [`../agent/README.md`](../agent/README.md).

Step-by-step: [../../docs/INSTALL.md](../../docs/INSTALL.md).

| Script | Run where | Does |
| --- | --- | --- |
| [`ct/defendsec.sh`](./ct/defendsec.sh) | Proxmox **host**, as root | Creates a Debian 12 LXC, then runs the server installer inside it |
| [`install-server.sh`](./install-server.sh) | Inside that CT, or any Linux VM | Installs Postgres, apid, console, and agent download files |
| [`uninstall-server.sh`](./uninstall-server.sh) | Inside the CT / Linux VM | Stops units; `--purge-data` / `--purge-postgres` are optional |

`ct/defendsec.sh` uses two storages:

- `TEMPLATE_STORAGE` — LXC templates (`vztmpl`), usually `local`
- `STORAGE` — the container disk (`rootdir`), often `local-lvm`

Copy-paste for a Proxmox host:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh)"
```

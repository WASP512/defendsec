# Agent packaging

Install this on **each machine you want to inventory**. Do not run the Proxmox helper here.

After the server is up, sign in and copy **Agent install** from the **Enroll** page. That command is the supported path.

| File | Purpose |
| --- | --- |
| [`install.sh`](./install.sh) | Download `defendsec-agentd`, install systemd, enroll |
| [`uninstall.sh`](./uninstall.sh) | Stop the agent; `--purge-data` removes `/var/lib/defendsec-agent` |

The server also publishes `install.sh` as `http://<server>:47261/downloads/install-agent.sh`.

Full guide: [../../docs/INSTALL.md](../../docs/INSTALL.md).

Uninstall without a git checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/agent/uninstall.sh | sudo bash
```

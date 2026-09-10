# Agent packaging

Separate from the Proxmox/server installer.

| File | Purpose |
| --- | --- |
| [`install.sh`](./install.sh) | Download binary, install systemd unit, enroll |
| [`uninstall.sh`](./uninstall.sh) | Stop the agent; optional `--purge-data` |

Served from the console after server install as `/downloads/install-agent.sh`.

See [`../../docs/INSTALL.md`](../../docs/INSTALL.md).

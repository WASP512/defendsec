# Operate DefendSec

Use this after a successful install. First-time setup is in [INSTALL.md](./INSTALL.md).

DefendSec is inventory plus host detection. It is **not** MDM: no wipe, lock, DEP, profiles, or CSP.

---

## Where things live

On a packaged server / Proxmox container:

| Path | What |
| --- | --- |
| `/opt/defendsec` | Source tree used to build the server |
| `/var/lib/defendsec` | Admin token, enroll secret, JSON store, PKI, downloads |
| `/etc/defendsec/apid.env` | API, database URL, tokens |
| `/etc/defendsec/console.env` | Console port, cookie, public URL |
| `defendsec-apid` / `defendsec-console` | systemd units |

On an enrolled host:

| Path | What |
| --- | --- |
| `/usr/local/bin/defendsec-agentd` | Agent binary |
| `/etc/defendsec/enroll-secret` | Enrollment secret |
| `/etc/defendsec/agentd.env` | Server addresses |
| `/var/lib/defendsec-agent` | Node key and agent state |

---

## Credentials

There is no username. Tokens are secrets.

| Role | How to retrieve (Proxmox) | Console access |
| --- | --- | --- |
| Admin | `pct exec <CTID> -- cat /var/lib/defendsec/admin-token.txt` | Full |
| Viewer (optional) | value of `DEFENDSEC_VIEWER_TOKEN` in `/etc/defendsec/apid.env` | Read-only |
| Enroll secret | `pct exec <CTID> -- jq -r .enrollSecret /var/lib/defendsec/defendsec.json` | Not a login; used only to enroll agents |

Set the **same** viewer token in both `apid.env` and `console.env`, then restart both units:

```bash
sudo systemctl restart defendsec-apid defendsec-console
```

Viewers sign in at `/login` with that token. They cannot enroll hosts, rotate the secret, change findings, or issue signed commands.

To enable a viewer on the next `install-server.sh` run:

```bash
sudo bash /tmp/defendsec-install-server.sh --viewer-token 'a-long-random-string'
```

Existing admin token and database password are kept on re-run unless you pass replacements.

---

## Logs and health

Inside the server:

```bash
systemctl status defendsec-apid defendsec-console
journalctl -u defendsec-apid -u defendsec-console -f
curl -fsS http://127.0.0.1:47261/login >/dev/null && echo console-ok
```

On an agent host:

```bash
systemctl status defendsec-agentd
journalctl -u defendsec-agentd -f
```

---

## Reverse proxy (HTTPS)

Port `47261` is HTTP. If users reach the console through HTTPS:

1. Terminate TLS on the proxy.
2. Forward to `http://127.0.0.1:47261`.
3. Send `X-Forwarded-Host` and `X-Forwarded-Proto`.
4. In `/etc/defendsec/console.env`:

   ```bash
   DEFENDSEC_COOKIE_SECURE=true
   DEFENDSEC_PUBLIC_CONSOLE_URL=https://defendsec.example.com
   ```

5. `sudo systemctl restart defendsec-console`

`DEFENDSEC_PUBLIC_CONSOLE_URL` is what the **Enroll** page prints for download URLs.

Keep `47262`/`47263` reachable by agents (or proxy them separately). Do not expose Postgres or port `47264`.

---

## Backup and restore

Backup (JSON store, PKI, admin token, optional Postgres dump):

```bash
sudo bash -c 'set -a; . /etc/defendsec/apid.env; \
  DEFENDSEC_DATA_DIR=/var/lib/defendsec /opt/defendsec/scripts/backup.sh'
```

The script prints the `.tar.gz` path.

Restore on a server that already has DefendSec installed:

```bash
sudo systemctl stop defendsec-console defendsec-apid
sudo bash -c 'set -a; . /etc/defendsec/apid.env; \
  DEFENDSEC_DATA_DIR=/var/lib/defendsec /opt/defendsec/scripts/restore.sh /path/to/backup.tar.gz'
sudo systemctl start defendsec-apid defendsec-console
```

Confirm hosts show in the console and agents reconnect with existing certificates.

From a source checkout instead of `/opt/defendsec`:

```bash
DEFENDSEC_DATA_DIR="$PWD/data" DATABASE_URL=postgres://... ./scripts/backup.sh
```

---

## Revoke a host certificate and re-enroll

1. Open the host page → **Revoke certificate**.
2. Live gRPC connections are dropped.
3. On the host, remove agent state and re-run the Enroll install command:

   ```bash
   sudo systemctl stop defendsec-agentd
   sudo rm -rf /var/lib/defendsec-agent
   # then paste the current Enroll command
   ```

---

## Alerts and signed commands

- **Alerts** lists FIM, SCA, and vulnerability findings when Postgres is running (packaged installs include Postgres).
- Acknowledge / resolve / reopen is admin-only.
- Open FIM drift and SCA findings can auto-resolve when the host returns to baseline.
- Host mutation is always Ed25519-signed: isolate, release, kill-by-name, live query, agent update, allowlisted scripts, quarantine path.
- Isolate only drops network if the agent is root **and** `DEFENDSEC_ISOLATE_NET=1`. Otherwise it is a flag in the console.

---

## Advisory ingest (optional)

The packaged server ships a local advisory catalog. To refresh from OSV on a timer, see [../scripts/ingest-osv.timer.md](../scripts/ingest-osv.timer.md) and `packaging/systemd/defendsec-ingest-osv.timer`. This is **not** enabled automatically.

---

## Data retention

When Postgres is enabled, apid prunes on startup:

| Data | Environment variable | Default |
| --- | --- | --- |
| Resolved alerts | `DEFENDSEC_ALERT_RETENTION_DAYS` | 90 days |
| Live query results | `DEFENDSEC_LIVE_QUERY_RETENTION_DAYS` | 30 days |

---

## Developer lab (not production)

Console + apid + agent on one machine:

```bash
docker compose up -d postgres
export DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec?sslmode=disable
go build -o bin/defendsec-apid ./cmd/defendsec-apid
go build -o bin/defendsec-agentd ./cmd/defendsec-agentd
DEFENDSEC_DATABASE_URL="$DATABASE_URL" ./bin/defendsec-apid
```

Another terminal:

```bash
npm install
npm run dev
```

Sign in with `data/admin-token.txt`. Enroll:

```bash
./bin/defendsec-agentd \
  --server-http https://127.0.0.1:47262 \
  --server-grpc 127.0.0.1:47263 \
  --tls-server-name localhost \
  --enroll-secret "$(jq -r .enrollSecret data/defendsec.json)" \
  --state-dir data/agent-mtls
```

Fedora-specific lab notes: [FEDORA.md](./FEDORA.md).

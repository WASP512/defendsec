# DefendSec operations runbook

Self-hosted Fleet-like inventory + Wazuh-shaped host detection. **Not MDM:** no wipe, lock, DEP, profiles, or CSP management.

Fedora workstation hands-on (dnf, firewalld, systemd, SELinux notes): [`FEDORA.md`](./FEDORA.md).

Production install and uninstall (Proxmox VE CT + separate agent download): [`INSTALL.md`](./INSTALL.md).

## Quick start (compose + apid + console + agent)

1. Start Postgres:

```bash
docker compose up -d postgres
export DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec?sslmode=disable
```

2. Build and run the control plane:

```bash
go build -o bin/defendsec-apid ./cmd/defendsec-apid
go build -o bin/defendsec-agentd ./cmd/defendsec-agentd
DEFENDSEC_DATABASE_URL="$DATABASE_URL" ./bin/defendsec-apid
```

3. Start the console (separate terminal):

```bash
npm install
npm run dev
```

Sign in with the admin token from `data/admin-token.txt` or `DEFENDSEC_ADMIN_TOKEN`.

4. Enroll one agent:

```bash
DEFENDSEC_APID=https://127.0.0.1:47262 \
DEFENDSEC_ENROLL_SECRET="$(jq -r .enrollSecret data/defendsec.json)" \
  ./bin/defendsec-agentd
```

Agents connect over mTLS gRPC on `:47263`. Signed commands are issued on loopback admin HTTP `:47264`.

## RBAC (admin vs viewer)

| Token | Source | Console | Admin API (`:47264`) |
| --- | --- | --- | --- |
| Admin | `DEFENDSEC_ADMIN_TOKEN` or `data/admin-token.txt` | Full | GET + POST (commands, revoke, alert status, …) |
| Viewer | Optional `DEFENDSEC_VIEWER_TOKEN` | Read-only (no response buttons, no alert status changes) | GET only; POST commands/revoke/alerts status → 403 |

Set the same viewer token in both apid and the Next.js process. Viewers sign in with that token at `/login`.

## Backup and restore

Create a tarball (JSON presence, PKI, optional Postgres dump):

```bash
DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec?sslmode=disable \
  ./scripts/backup.sh
```

Restore on a clean VM (stop apid/console first):

```bash
DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec?sslmode=disable \
  ./scripts/restore.sh data/backups/defendsec-YYYYMMDDTHHMMSSZ.tar.gz
```

Verify: hosts appear in the console, alerts/commands tables present, agents reconnect with existing certs.

## CA revoke and re-enroll

1. From host detail → **Revoke certificate** (or `POST /v1/revoke` on admin API).
2. Revoked fingerprints are stored in `revoked_certs`; live gRPC connections receive `PermissionDenied`.
3. On the host, remove agent state under the agent data dir and re-run enroll with the enroll secret.
4. Audit log records `cert_revoke`; old device row remains for history.

## Agent update apply

1. Publish a release: `POST /v1/agent-releases` with `version`, `url`, `sha256`, optional `channel`.
2. From host **Signed response** → **Push agent update**, or issue `agent_update` command manually.
3. Agent downloads, verifies SHA256, replaces its binary, and exits; systemd (or your supervisor) should restart it.

## Alert triage

- **Alerts** page filters by status/kind/device.
- Each alert carries **detected** vs **ingested** time plus a **generator** id (`defendsec.fim` / `.sca` / `.vuln`) and a stable `detail` contract (`file.path`, `event.action`, `sca.*`, `package.*`, `advisory.*`, plus `raw` for replay).
- Acknowledge / resolve / reopen (admin only). Open FIM drift and SCA findings auto-resolve when the host returns to baseline / checks pass.
- **FIM critical/high:** use **Suggest isolate** (confirmation required; does not auto-run).
- **SCA high/critical:** open the host response panel or filter SCA alerts for that device.
- **Vuln:** link to **Advisories** for package/CVE context (Fedora RPM aliases such as `openssh-server` ↔ `openssh`, `openssl-libs` ↔ `openssl`).
- Every signed command is audited as `command_issue` (admin) and `command_ack` (agent).

## Data retention

On apid startup (when Postgres is enabled), old rows are pruned:

| Data | Env | Default |
| --- | --- | --- |
| Resolved alerts | `DEFENDSEC_ALERT_RETENTION_DAYS` | 90 days |
| Live query results | `DEFENDSEC_LIVE_QUERY_RETENTION_DAYS` | 30 days |

Optional OSV ingest timer: see `packaging/systemd/defendsec-ingest-osv.timer`.

## Active response commands

All host mutation is Ed25519-signed via apid. Allowlisted types include `isolate`, `release`, `kill_process`, `live_query`, `agent_update`, `run_script` (allowlisted script ids only), and `quarantine_path` (FIM watch paths or `/tmp/defendsec-quarantine` staging only).

## Explicit non-MDM wall

DefendSec does **not** implement mobile device management. Device lock/wipe, supervision profiles, configuration profiles, and enterprise policy delivery are out of scope. Use Scope page and this runbook to set expectations for operators.

## Packaging (systemd sketches)

Example units live under `packaging/systemd/`:

- `defendsec-apid.service` — control plane + admin API
- `defendsec-agentd.service` — enrolled host agent
- `defendsec-ingest-osv.timer` + `.service` — optional advisory refresh

Adjust paths, users, and environment files for your distribution.

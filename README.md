# DefendSec

Self-hosted **security inventory** for machines you enroll. No accounts, premium flags, or subscriptions.

The agent reports versions, pending patches, and hashes of a small file set. The console matches software against a local advisory catalog, tracks integrity drift, and runs snapshot policies. This is not FleetDM and it is not MDM.

The in-app [Scope](/scope) page maps what is easy, what is ordinary (OSV/NVD ingest, patch orchestration), and where vendor MDM becomes the wall.

The detailed post–Phase-6 roadmap (Fleet-like ops + Wazuh-like detection, still not MDM) lives in [`docs/NEXT-PHASES.md`](docs/NEXT-PHASES.md).

**Fedora workstation hands-on:** [`docs/FEDORA.md`](docs/FEDORA.md) (dnf inventory, firewalld, systemd units, isolate notes).

**Install (Proxmox CT + separate agent download):** [`docs/INSTALL.md`](docs/INSTALL.md).

## Run the console

```bash
npm install
npm run dev
```

Open [http://127.0.0.1:47261](http://127.0.0.1:47261) and sign in.

- Development (when `DEFENDSEC_ADMIN_TOKEN` is unset): token is `defendsec-local-admin`, also written to `data/admin-token.txt`.
- Production: set `DEFENDSEC_ADMIN_TOKEN`, or let the first start create a random value in `data/admin-token.txt`.

The console cookie is httpOnly. Agent enroll/check-in do **not** use the admin token: they use the enroll secret and node key only.

Host state is `data/defendsec.json`. A copy is kept at `data/defendsec.json.bak` after each successful save. If `defendsec.json` is corrupt, DefendSec refuses to overwrite it — restore the `.bak` yourself.

Integrity policy compares current hashes to an **accepted baseline** (first check-in, or **Accept current as baseline** on the host page). The event list is an audit log and does not keep the host failing forever.

```bash
npm run build
npm start
```

## Enroll a host

```bash
python3 agent/defendsec-agent.py --server http://YOUR_SERVER:47261 --enroll-secret SECRET
```

Copy the exact command from **Enroll**. Python 3 standard library only. Re-enrolling the same hostname reuses the existing node key so a running agent is not invalidated.

Optional extra integrity paths (OS path separator):

```bash
DEFENDSEC_FIM_PATHS=/etc/hostname python3 agent/defendsec-agent.py --server URL --enroll-secret SECRET --once
```

## What you get

- Admin token for the console (cookie or `Authorization: Bearer`)
- Host list with online/offline (two-minute window)
- Software version records across hosts
- Pending patches (`apt list --upgradable` on Debian/Ubuntu)
- Advisory matches from `lib/advisories.ts` with acknowledge / reopen
- File integrity on `/etc/passwd`, `/etc/hosts`, `sshd_config`, and similar
- Policies: check-in, encryption, firewall, supported OS, high/critical advisories, patches, FIM

## What you do not get

- Live NVD/OSV synchronization (the catalog is local on purpose)
- Remote patch install / reboot orchestration
- Lock, wipe, DEP, configuration profiles, Windows CSP
- Enterprise FIM (inotify, signed baselines, noisy-path tuning)

If you need stolen-device wipe, keep a real MDM next to this plane.

## Phase 1: mTLS agent transport

The Python HTTP agent still reports inventory. Phase 1 adds a Go control plane and daemon that enroll over HTTPS, pin the CA, then keep an mTLS gRPC heartbeat and bidirectional stream.

Unsigned control commands are **rejected**. Isolate, release, and kill-by-name are signed (Phase 2).

```bash
# Go 1.22+
make apid agent
# Console must have created data/defendsec.json first (npm run dev), or pass --enroll-secret
./bin/defendsec-apid --data-dir data
./bin/defendsec-agentd \
  --server-http https://127.0.0.1:47262 \
  --server-grpc 127.0.0.1:47263 \
  --tls-server-name localhost \
  --enroll-secret YOUR_ENROLL_SECRET \
  --state-dir data/agent-mtls
```

- HTTPS enroll/health: `:47262` (`GET /healthz`, `GET /v1/ca`, `POST /v1/enroll`)
- gRPC mTLS: `:47263` (`Heartbeat`, `Connect` stream with server pings)
- Presence file: `data/defendsec-agents.json` (the console merges these hosts into Fleet)
- PKI: `data/pki/` (ECDSA P-256 CA + server cert, TLS 1.3)
- Packaging sketches: `packaging/systemd`, `packaging/launchd`, `packaging/windows`

First `GET /v1/ca` is trust-on-first-use. After that the agent verifies the control plane with the pinned CA and presents a client certificate whose CN is the device id.

## Phase 2: signed isolate and kill

The control plane keeps an Ed25519 key in `data/pki/control-ed25519.key`. The console (admin cookie) posts to Next.js, which calls loopback `http://127.0.0.1:47264/v1/commands` with the admin token. `defendsec-apid` signs the command; `defendsec-agentd` verifies device id, expiry, and signature before acting.

| Type | Effect |
| --- | --- |
| `isolate` | Sets an isolation flag the console shows. Network drop only if the agent is root **and** `DEFENDSEC_ISOLATE_NET=1`. |
| `release` | Clears that flag. |
| `kill_process` | `SIGTERM` to processes whose `/proc/pid/comm` matches a strict name. Refuses systemd, sshd, defendsec-agentd, defendsec-apid, init, next-server. |

Unsigned or wrong-device commands are rejected. Open a host that has an mTLS agent and use **Signed response**.

```bash
make test-go
```

## Phase 3: inventory over mTLS

`defendsec-agentd` now collects the same snapshot the Python agent does (packages, apt pending updates, encryption/firewall, FIM hashes) and sends `ReportInventory` over gRPC. The console merges that into Fleet, Versions, Patches, Advisories, Policies, and Integrity.

Python HTTP check-in still works. A host only needs one of the two agents.

The first FIM report is the accepted baseline. Drift is stored in `data/defendsec-agents.json` (`fimEvents`). **Accept current as baseline** on an mTLS host calls defendsec-apid.

## Phase 4: Postgres, audit, revoke

Optional durable store. File JSON remains the console source of truth; apid dual-writes when a database URL is set.

```bash
docker compose up -d postgres
export DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec
./bin/defendsec-apid --data-dir data --db-url "$DEFENDSEC_DATABASE_URL"
```

Admin loopback (`:47264`) gains:

| Route | Purpose |
| --- | --- |
| `GET /v1/audit` | Recent audit events |
| `POST /v1/revoke` | Revoke a device cert fingerprint (mTLS rejected afterward) |
| `GET/POST /v1/advisories` | List / import advisory rows |
| `GET/POST /v1/agent-releases` | Publish / read agent update channel metadata |

Console **Audit** reads Postgres when `DATABASE_URL` / `DEFENDSEC_DATABASE_URL` is set for Next.js.

## Phase 5: OSV ingest, real isolate, continuous FIM

```bash
# OSV → advisories table (requires network + psycopg, or --via admin)
pip install psycopg
DEFENDSEC_DATABASE_URL=postgres://defendsec:defendsec@127.0.0.1:5432/defendsec \
  python3 scripts/ingest-osv.py --packages openssl,openssh-server,git
```

Network isolate: run the agent as root with `DEFENDSEC_ISOLATE_NET=1`. The agent installs an `iptables` chain `DEFENDSEC_ISOLATE` that rejects new egress while keeping loopback and established flows (so the control channel survives).

Continuous FIM: `defendsec-agentd` watches inventory FIM paths with `fsnotify` and triggers an immediate inventory report on change (debounced). Override paths with `DEFENDSEC_FIM_PATHS`.

## Phase 6: agent update channel, live query, backup

Signed command types:

| Type | Effect |
| --- | --- |
| `live_query` | Allowlisted snapshot: `processes`, `listening_ports`, `users`, `os_info` |
| `agent_update` | Stages `pending-update.json` in the agent state dir for an external updater |

```bash
./scripts/backup.sh
./scripts/restore.sh data/backups/defendsec-YYYYMMDDThhmmssZ.tar.gz
```

Backup captures JSON store, PKI, and `pg_dump` when a database URL is present.

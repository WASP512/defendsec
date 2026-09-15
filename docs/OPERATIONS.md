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

## Updates

Open **Operations → Updates** in the console. DefendSec checks the latest stable
GitHub release and compares it with the installed version.

- **Install update** downloads the architecture-matched API and standalone
  console, verifies every file against `SHA256SUMS`, creates a private backup
  of DefendSec state and Postgres, restarts both services, and rolls back the
  binaries automatically if either health check fails.
- **Update outdated agents** queues signed, architecture-matched update commands
  for connected mTLS agents. Each agent verifies its binary before replacement.
- Viewer sessions can inspect update status but cannot start an update.

Existing source-built installations need one final installer re-run to install
the privileged update helper and its narrowly scoped systemd permission:

```bash
curl -fL https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/install-server.sh \
  -o /tmp/defendsec-install-server.sh
sudo bash /tmp/defendsec-install-server.sh
```

Updates are always operator-approved. DefendSec does not silently update the
server or enrolled agents.

If an update fails, inspect:

```bash
systemctl status defendsec-update.service
journalctl -u defendsec-update.service --no-pager -n 100
cat /var/lib/defendsec/update-status.json
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

The script prints the `.tar.gz` path. Backups older than `DEFENDSEC_BACKUP_RETENTION_DAYS` (default 14) in the same directory are pruned automatically after each run.

**Schedule it.** A manual backup you remember to run is not a backup plan. `packaging/systemd/defendsec-backup.service` and `defendsec-backup.timer` run the command above daily. This is **not** enabled automatically:

```bash
sudo install -m 0644 packaging/systemd/defendsec-backup.service /etc/systemd/system/
sudo install -m 0644 packaging/systemd/defendsec-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now defendsec-backup.timer
```

Verify it: `systemctl list-timers defendsec-backup.timer` and `journalctl -u defendsec-backup.service`. Copy the resulting `.tar.gz` files off the host on your own schedule — a backup that only ever lives on the machine it backs up is not a disaster-recovery plan either.

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

## Compliance and audit evidence

The **Compliance** page shows per-control status for a framework over a window: CIS Controls v8,
NIST SP 800-171, CMMC 2.0 Level 2, NIST SP 800-53 Rev 5 and the CJIS Security Policy v6.0.

Read the statuses carefully — two of them are easy to confuse and mean opposite things.

| Status | What it means |
| --- | --- |
| Satisfied | Evidence across the window, nothing outstanding when it closed |
| Deficient | Findings were still open at the close of the window |
| Accepted deficiency | Still open, covered by a documented, time-limited exception. **Not a pass** |
| No evidence recorded | DefendSec *can* evidence this and recorded nothing. Usually the check never ran |
| Outside DefendSec | DefendSec *cannot* evidence this at all. Cover it another way |

"No evidence recorded" is the one to watch. It is not a pass and it is not a scope boundary — it
almost always means a check is not running on the hosts you think it is.

There is no overall score, on purpose. A coverage percentage is where a control nobody has looked
at disappears into a rounding error.

A control marked **partial coverage** is satisfied only for the part DefendSec can see. Each one
says which part it does not cover; read the note before citing it.

### Audit periods

An assessment is about a window, so define the window under review:

```bash
curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"CJIS FY26","framework":"cjis-v6",
       "startsAt":"2026-01-01T00:00:00Z","endsAt":"2026-12-31T23:59:59Z"}' \
  http://127.0.0.1:47264/v1/audit/periods
```

Closing a period (`POST /v1/audit/periods/close` with `{"periodId":"...","closed":true}`) declares
it final. Reopening is allowed, and both are recorded in the ledger.

### Documented exceptions

When a control cannot be met and the agency accepts that, record it rather than explaining it to
the assessor from memory:

```bash
curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"controlId":"cis-v8:5.4","periodId":"<period id>",
       "reason":"legacy jump host pending decommission",
       "remediation":"replaced in Q3","owner":"ops",
       "expiresAt":"2026-09-30T00:00:00Z"}' \
  http://127.0.0.1:47264/v1/audit/exceptions
```

An expiry is required. An exception with no expiry is a permanent excuse, and DefendSec will not
store one. When it lapses, the control returns to **Deficient** by itself.

This is not a POA&M product. It records the exception, its owner and its expiry — it does not do
approval routing or risk scoring.

### Exporting evidence for an assessor

```bash
# Everything, unscoped
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -OJ http://127.0.0.1:47264/v1/audit/evidence

# Scoped to a framework and a period, which adds the assessment to the bundle
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -OJ "http://127.0.0.1:47264/v1/audit/evidence?periodId=<period id>"
```

Verify it with the server switched off — that is the point of it:

```bash
defendsec-verify defendsec-evidence-*.json
```

The scope does **not** narrow the audit range. A hash chain filtered by content is not a chain, so
the bundle carries the whole range and expresses its scope through what it asserts.

**What the bundle proves, and what it does not.** The chain, the checkpoints and the command
signatures verify on their own. The assessment does not: audit-entry counts are recomputed from
the bundle's own chained entries and checked, but alert and command counts come from records that
are not chained. `defendsec-verify` prints that distinction, and the bundle carries it in a
provenance line that verification checks has not been edited. Hand an assessor the bundle, not a
screenshot.

### Control tags

Every finding, signed action and ledger entry is tagged with the controls it speaks to at the
moment it is written, so a period that has already closed reports what was true then rather than
what today's mapping would say. Rows written before the tagging migration carry no tag; they are
not backfilled, because backfilling would manufacture a claim that never existed.

The SCA packs in `packs/sca/` name their own controls per check. A bad identifier fails the pack
load rather than loading quietly — a pack that looks tagged and evidences nothing is the failure
mode hardest to notice.

`GET /v1/controls` serves the whole catalog, including every control DefendSec cannot evidence,
each with the reason.

---

## FIPS 140-3 mode

CJIS and several federal regimes require cryptography from a FIPS 140-3 validated module.
DefendSec has no crypto of its own beyond two exceptions named below, so this is a matter of
starting the Go runtime in the right mode and selecting an approved password KDF.

**To enable it**, run apid with Go's FIPS mode and DefendSec's own switch:

```
Environment=GODEBUG=fips140=only
Environment=DEFENDSEC_FIPS_MODE=1
```

`GODEBUG=fips140=on` is the weaker setting: it routes standard-library cryptography through the
validated module but **rejects nothing**. A deployment can run under it while hashing passwords
with an algorithm SP 800-132 does not approve, and nothing anywhere reports a problem. Use
`=only`, which rejects non-approved use.

`DEFENDSEC_FIPS_MODE=1` is what selects the approved password KDF. Set it even under `=only`,
and set it on its own if you are required to use approved algorithms but cannot run the Go
module in FIPS mode. `GODEBUG=fips140` alone is also honoured, so a deployment that only sets
that still gets approved password hashing.

**Verify what is actually in force** — not what was intended — with the admin API:

```
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:8443/v1/crypto-posture
```

It reports the Go module state, whether approved algorithms are being required, the password KDF
in use, and the deviations in plain words. Hand it to an assessor rather than asserting the
posture from configuration.

### What changes, and what does not

| Surface | Algorithm | Under FIPS |
| --- | --- | --- |
| Command signatures | Ed25519 (FIPS 186-5) | Unchanged; verified under `fips140=only` |
| Acknowledgement signatures | ECDSA P-256 | Unchanged |
| Audit chain and checkpoints | SHA-256 | Unchanged |
| Session and enrollment tokens | `crypto/rand` | Unchanged |
| Password hashing | Argon2id → PBKDF2-HMAC-SHA256 | **Changes** |
| Second-factor codes | HMAC-SHA1 | Runs outside enforcement |

Two things need a decision; neither is the signing path.

**Passwords.** Argon2id is memory-hard and the better defence against offline cracking, so it
stays the default. It is not FIPS-approved, and its Blake2b comes from `golang.org/x/crypto` and
never enters the validated boundary — which is why `fips140=on` does not catch it. In FIPS mode
new hashes use PBKDF2-HMAC-SHA256 at 600,000 iterations (SP 800-132).

Both formats verify in either mode, so switching a running deployment to FIPS does not lock out
existing accounts. An account whose stored hash uses the other algorithm is re-hashed
transparently on its owner's next successful login. Re-hashing needs the plaintext, so an account
that never logs in keeps its old hash until its password is next set; if approved hashing must
hold for every account, force a password reset.

**Second-factor codes.** TOTP uses HMAC-SHA1, which every authenticator app implements. HMAC-SHA1
is approved for HMAC under SP 800-131A, but Go's `fips140=only` restricts HMAC to SHA-2 and SHA-3
and *panics* rather than returning an error. Changing the digest would break Google Authenticator,
Aegis, 1Password and the rest for no security gain, so that one HMAC is computed inside
`fips140.WithoutEnforcement`. The deviation is marked in code and disclosed by
`/v1/crypto-posture` rather than hidden.

### What this does not claim

Running in FIPS mode is not a validation. Go's module carries its own CMVP certificate status,
which is the Go project's to hold, not DefendSec's; the operating system's own module (for TLS
termination in a reverse proxy, disk encryption, Postgres) is separately in scope for an
assessor. DefendSec's claim is narrower and checkable: the algorithms it uses are approved ones,
the exceptions are named, and the posture is reported by the running process.

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

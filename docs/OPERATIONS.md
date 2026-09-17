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

## HTTPS

The console is served over HTTPS by default (roadmap 5.3). `defendsec-web` terminates TLS on port
`47261` and forwards to the Next.js console, which binds to loopback only — Next.js does not serve
HTTPS in production, and the documented answer is a reverse proxy, so DefendSec ships one rather
than asking every operator to install and configure their own.

The admin token is a bearer credential. On plain HTTP it is readable by anything on the path, and a
product that signs every host action while handing its own admin token around in clear text is not
making a coherent argument.

| Mode | `DEFENDSEC_TLS` | When |
| --- | --- | --- |
| Self-signed | `on` (default) | A LAN with no DNS and no internet. The browser warns, honestly |
| Let's Encrypt | `acme` | A public DNS name and inbound port 80 |
| Your own certificate | `file` | An internal CA — the way to stop the warning without exposing the box |
| Plain HTTP | `off` | An isolated lab, explicitly, and logged at every start |

Configure in `/etc/defendsec/web.env`, then `systemctl restart defendsec-web`. An unrecognised
value refuses to start rather than falling back — silently serving plain HTTP because somebody
typed `tls` instead of `on` would undo the point.

### The self-signed certificate

Generated on first start, kept in `/var/lib/defendsec/tls`, and reused across restarts — a new
fingerprint every restart would train operators to click through the warning. It covers the names
in `DEFENDSEC_TLS_HOSTS` plus loopback always, so you can reach the console from the box even when
DNS is wrong, which is exactly when you need to. It is regenerated when it nears expiry or when you
add a hostname.

Verify it rather than clicking through blind. The server logs the fingerprint at startup:

```bash
journalctl -u defendsec-web --no-pager | grep "console certificate"
```

Compare that against what your browser shows. With a self-signed certificate this comparison is
the only verification available.

### Let's Encrypt

```bash
DEFENDSEC_TLS=acme
DEFENDSEC_TLS_HOSTS=defendsec.example.com
DEFENDSEC_WEB_HTTP_ADDR=:80
DEFENDSEC_ACME_ACCEPT_TOS=1
DEFENDSEC_ACME_EMAIL=security@example.com
```

Only the names you list are requested — without that allowlist, anyone pointing a DNS record at
the box could have a certificate minted and exhaust your rate limit. An IP address or a `.local`
name cannot be issued a public certificate, and DefendSec says so at startup rather than failing
opaquely at renewal.

### Turning it off

```bash
# /etc/defendsec/web.env
DEFENDSEC_TLS=off
# /etc/defendsec/console.env — a Secure cookie is not sent over plain HTTP,
# so leaving this true would make login fail with no useful error.
DEFENDSEC_COOKIE_SECURE=false
```

### Your own reverse proxy

If you already run one, point it at the console directly on `127.0.0.1:47265`, set
`DEFENDSEC_TLS=off` for the front-end (or do not run `defendsec-web` at all), and forward
`X-Forwarded-Host` and `X-Forwarded-Proto` — the console builds absolute URLs and decides cookie
flags from them.

`DEFENDSEC_PUBLIC_CONSOLE_URL` is what the **Enroll** page prints for download URLs.

Keep `47262`/`47263` reachable by agents. Do not expose Postgres, port `47264`, or `47265`.

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

| Data | Environment variable | Default | Pruned? |
| --- | --- | --- | --- |
| Audit ledger | — | forever | **Never.** Removing entries would break the hash chain, which is the point of it |
| Command history (Postgres) | — | forever | Never |
| Command history (JSON file) | `DEFENDSEC_COMMAND_RETENTION_DAYS` | 365 days | By age |
| Resolved alerts | `DEFENDSEC_ALERT_RETENTION_DAYS` | 365 days | By age, **resolved only** — an open finding is never deleted |
| Live query results | `DEFENDSEC_LIVE_QUERY_RETENTION_DAYS` | 30 days | By age |

Defaults are one year, the CJIS Policy Area 4 minimum. DefendSec's compliance view claims to
evidence audit retention, so a default below the minimum of a framework it names would make that
claim false out of the box. A negative value keeps everything; zero restores the default rather
than meaning "keep nothing".

**The JSON command log used to be a 500-record ring buffer**, discarding the oldest privileged
action regardless of age. On a busy fleet that could push a month of signed actions out of the
file in an afternoon. It is now retained by age; the remaining size cap is a safety valve, and
crossing it is logged at error level rather than happening silently. Configure Postgres — it holds
the authoritative history with no cap at all.

### Check what is actually retained

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/retention
```

It reports the configured windows **and how much history is really held**. That second number is
the one an assessor wants: retention configuration does not create history that was never
recorded, so a one-year policy on a system installed last month evidences one month.

---

## Response policy

Before Phase 2, an admin token could issue any command to any host. Now a **deny-by-default policy
engine sits between the API and the signer**: a command no rule permits is never signed, so it
cannot run even if the console is bypassed entirely — the agent checks a signature that was never
produced. A UI that hides a button enforces nothing; an unsigned command is inert.

```bash
DEFENDSEC_POLICY_FILE=/etc/defendsec/policy.yaml
```

**Without this set, every host command is refused.** That is the correct posture for an
unconfigured response tool, and apid says so loudly at startup. Start from the shipped example:

```bash
sudo cp /opt/defendsec/packaging/policy/default.yaml /etc/defendsec/policy.yaml
```

Keep it in version control. "Who changed this rule, and when" is the first question asked after a
command that should not have been permitted, and a policy editable only through a web form has no
answer. A file that fails to parse **refuses to start** rather than half-loading — the rules that
failed to parse are exactly the ones nobody notices are missing — and a misspelled key is an error,
because silently dropping `host_clases` turns a narrow rule into a fleet-wide one.

### How rules are evaluated

1. Any matching **deny** wins, regardless of where it sits in the file. Order-dependent policy is
   policy nobody can reason about.
2. Otherwise the **strictest matching permit** applies, so adding a permissive rule never silently
   removes an approval requirement.
3. If nothing matches, the command is **denied**.

```yaml
rules:
  - id: isolate-production-needs-two
    effect: permit
    commands: [isolate]
    roles: [admin]
    host_classes: [production]
    require_approvals: 2

  - id: never-disrupt-domain-controllers
    effect: deny
    commands: [kill_process, quarantine_path, run_script]
    host_classes: [domain-controller]
    reason: >-
      A domain controller losing a process takes estate-wide authentication
      down. Isolate it instead.

limits:
  - id: isolate-fleet-hourly
    commands: [isolate]
    scope: fleet      # fleet is the default; a per-host cap would let a
    max: 5            # runaway isolate the estate one host at a time
    per: 1h
```

A `reason` is **required** on every deny rule and is returned to whoever the rule stops. A refusal
that says only "forbidden" produces a support ticket and then a request for a bypass; one that
names the rule produces a conversation about the rule.

### Host classes

Rules match on classes carried by the host, so they stay correct as the estate changes:

```bash
curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"deviceId":"<id>","classes":["production","critical"]}' \
  http://127.0.0.1:47264/v1/policy/host-classes
```

Reclassifying a host changes what policy permits against it, so it is an authorisation change and
is recorded in the ledger.

### Two-person integrity

A command whose rule sets `require_approvals: 2` comes back `202 Accepted` and is stored
**unsigned** — deliberately not a signed command with a pending flag, so flipping a status column
in the database yields nothing an agent will execute. Approvals are keyed on (request, actor), so
the same administrator clicking twice is one approval.

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/policy/approvals

curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' -d '{"pendingId":"<id>"}' \
  http://127.0.0.1:47264/v1/policy/approvals
```

On the final approval the command is **re-evaluated against policy** before signing. Minutes have
passed: a limit may now be exhausted, a window may have closed, the host may have been
reclassified. Requests expire after 30 minutes, because one that never expires is a way to get a
command signed weeks later under conditions nobody re-examined.

### Break-glass

A time-boxed bypass for an emergency policy did not anticipate:

```bash
curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"justification":"active ransomware on the finance segment","minutes":30}' \
  http://127.0.0.1:47264/v1/policy/break-glass
```

A written justification of at least 20 characters is required and is shown to every administrator
as an undismissable banner until it expires. Maximum four hours — an emergency lasting longer is a
situation, and a situation should have a rule.

**Two things it does not override**, by design:

- **An explicit deny.** A bypass is for reaching what policy never anticipated, not for doing the
  one thing it went out of its way to forbid.
- **A two-person requirement.** The whole point of that control is that one person cannot act
  alone; a bypass one person can open would remove it.

### Playbooks

Named, reviewable sequences in `DEFENDSEC_PLAYBOOK_DIR`:

```bash
DEFENDSEC_PLAYBOOK_DIR=/etc/defendsec/playbooks
```

A playbook is **not an authority**. Every step is signed and policy-checked individually, at the
moment it runs, against the host it targets — a sequence that executed three commands on one
policy decision would be a way to smuggle past the engine. A step that is refused or needs a
second approver **halts the run** rather than being skipped: skipping quietly turns a four-step
response into a three-step one, and the missing step is usually the dangerous one.

Steps can reference the triggering finding (`{{alert.path}}`, `{{alert.deviceId}}`, and so on).
A placeholder must be the **whole value**, never embedded in a longer string — these paths come
from files on a possibly-compromised host, and interpolating one into a payload would let a
crafted filename rewrite the rest of the command.

### Automatic response

Setting `automatic: true` on a playbook lets it run without anyone pressing a button. Three gates
must all agree: the playbook opts in, its trigger matches, and **policy permits every step**. The
human confirmation is replaced by policy, not removed. A second brake suppresses repeat automatic
runs of the same playbook on the same host for an hour, which stops the loop where a playbook
triggers on a finding it caused.

The shipped example that runs automatically only performs a `live_query`. Nothing that changes
state ships as automatic, and you should hold anything you add to the same bar until you trust the
trigger on your own estate.

### Reviewing decisions

Every evaluation, permit and deny alike, goes to the tamper-evident ledger with the SHA-256 of the
policy document that made it — so "what did the policy say at the time" is answerable from the
ledger rather than from what is on disk today. The **Response** page shows the rules, the pending
approvals and the recent decisions.

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  'http://127.0.0.1:47264/v1/policy/decisions?effect=deny'
```

Denials are the half that matters after an incident. "Did anyone try" is a question only a
deny-by-default engine can answer.

---

## Transparency anchoring

The hash chain defeats anyone who can edit the database. Signed checkpoints defeat anyone who can
append to it. Neither defeats an attacker who owns the server, the database **and** the control
signing key: that attacker can rebuild the whole ledger and sign a fresh checkpoint over it, and
the result verifies perfectly.

Anchoring publishes checkpoint hashes where that attacker cannot reach back and change them. They
can stop new anchors appearing; they cannot rewrite the ones already out there, so a rebuilt chain
stops matching and the forgery becomes visible.

Configure targets as a comma-separated list in `/etc/defendsec/apid.env`:

```bash
DEFENDSEC_ANCHOR_TARGETS='rfc3161=https://freetsa.org/tsr,file=/var/lib/defendsec/anchors'
DEFENDSEC_CHECKPOINT_INTERVAL=6h
```

A mistyped target refuses to start rather than being skipped — an operator who believes they have
anchoring they do not have stops looking.

| Kind | Form | What it is worth |
| --- | --- | --- |
| `rfc3161` | `rfc3161=<tsa url>` | Strongest. A third party signs that this hash existed at this time, and DefendSec never holds that key |
| `file` | `file=<directory>` | Exactly what you do with the directory. Pointed at a git worktree that is committed and pushed, strong. Left on the same disk as the database, nearly worthless |
| `peer` | `peer=<url>#<shared token>` | Mutual and free. Two agencies anchoring each other both gain, and compromising one does not reach the other's copy |

Only the hash is sent. A timestamp authority learns nothing about what the ledger contains, which
matters when the ledger describes an agency's security posture.

### The file target and git

The file target appends one JSON object per line to `anchors-YYYY-MM.jsonl`. It is append-only by
intent: the file is never rewritten, so a diff shows additions and nothing else, and a history that
only ever grows makes an alteration obvious to whoever reviews the repository.

Point it at a checkout and commit on a timer:

```bash
cd /var/lib/defendsec/anchors && git add -A && git commit -m "anchors" && git push
```

The value is entirely in the push. Anchors that never leave the machine protect nothing.

### Anchoring for a peer

To hold another instance's checkpoints, set a shared token:

```bash
DEFENDSEC_PEER_ANCHOR_TOKEN='a-long-random-string'
```

The peer then uses `peer=https://your-console/v1/anchors/receive#a-long-random-string`. The token is
separate from the admin token on purpose: a peer that anchors for you never holds admin access to
your instance. Without the variable set, the endpoint refuses everything — holding anchors is opt-in.

Peer anchors are stored apart from your own. They are somebody else's evidence held on their
behalf, and mixing the two would let a compromised peer's claims be read as yours.

### Checking them

The comparison is the entire point, and it is the step that is usually skipped: anchors written and
never checked detect nothing. The **Audit** page shows it, and so does the API:

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/audit/anchors | jq .summary
```

A mismatch means the chain was rebuilt after that anchor was published. A valid signature over the
current chain does **not** clear it — that signature is exactly what an attacker with the key would
produce.

`POST` to the same endpoint anchors the newest unanchored checkpoint immediately.

### What DefendSec checks, and what it leaves to you

For RFC 3161, DefendSec builds the request with a nonce, checks the authority's status, and
verifies that the returned token timestamps **the hash it asked about** with **the nonce it sent** —
which is what stops a compromised server presenting a token captured earlier for a hash it has
since rewritten.

It does **not** validate the authority's signature or certificate chain. That needs a full CMS
implementation and a trust store of TSA roots, and a half-done version would be worse than none: it
would report "verified" on the strength of checks it did not really make. The token is stored whole
so you can do it with tooling that already exists:

```bash
# Extract the token and the hash it covers, then verify against your TSA roots
openssl ts -verify -in token.tsr -data hash.bin -CAfile tsa-roots.pem
```

---

## Behavioural detection

DefendSec watches what hosts *do*, not only what state they are in. Process events are matched
against Sigma rules, and a match becomes an alert carrying the process lineage that led to it —
which a state-based check cannot provide, because by the time a file hash changes the process that
changed it has usually exited.

```bash
# /etc/defendsec/apid.env
DEFENDSEC_SIGMA_DIR=/opt/defendsec/packs/sigma
```

Rules are [Sigma](https://sigmahq.io/), so rules from community repositories work as they are.
Unlike policy and configuration packs, a rule that will not compile is **skipped rather than
fatal** — a rule directory is routinely a synced copy of thousands of community rules, a fraction
of which use features no single engine implements, and refusing to start because of an unrelated
one would leave you with no detection at all. Skipped rules are logged individually and listed in
the coverage view.

Not implemented, and refused at load rather than silently mis-evaluated: aggregation conditions
(`| count() > 5`), unknown field modifiers, and references to selections that do not exist. Each
would otherwise compile into something that means a different thing.

### What the sensor can and cannot see

There are two sensors, and which one you get changes your coverage materially. The agent logs
which it chose at startup, along with its limitations, and the coverage view shows the capability
of the one actually running.

**eBPF (`ebpf-exec`) — preferred.** Hooks the execve tracepoints and sees *every* successful exec,
with the argument vector as the caller passed it. Requirements:

- Linux **5.8 or later**, for BPF ring buffers.
- Kernel **BTF** (`CONFIG_DEBUG_INFO_BTF`, i.e. `/sys/kernel/btf/vmlinux` exists).
- Privilege to load a program — root, or `CAP_BPF` + `CAP_PERFMON`, plus `CAP_SYS_RESOURCE` on
  kernels before 5.11.
- **tracefs mounted** at `/sys/kernel/tracing`. systemd mounts it by default; minimal containers
  often do not.

What it still cannot see: execve only, so a `fork` with no following exec is not reported, and nor
are `execveat` callers. The first 16 arguments are recorded, 128 bytes each — longer vectors are
**flagged truncated in the event**, never silently clipped. Network connections, file writes,
privilege transitions and module loads have no sensor at all.

**`/proc` polling (`proc-poll`) — fallback.** Used when any requirement above is unmet. The agent
logs the specific reason at **warning** level, because this is a real reduction in coverage:

- It **samples**, every 250ms. A process that starts and exits between samples is never seen —
  and `curl … | sh` is short-lived. This is not a tuning problem; it is what sampling means.
- It reads the command line after the process started, so a process that rewrites its own argv is
  recorded as it rewrote itself.
- Same missing kinds as above.

If you see `eBPF sensor unavailable` in the agent log, the `reason` field names the specific
requirement that was not met. Fixing it is usually worth doing: the gap between the two sensors is
exactly the class of short-lived, scripted execution that matters most.

To rebuild the BPF object after editing `internal/sensor/bpf/exec.bpf.c`:

```bash
apt install clang llvm libbpf-dev   # or: dnf install clang llvm libbpf-devel
make bpf
```

The compiled object is committed, so building the agent itself needs none of that.

### Coverage, blind spots first

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/detection/coverage
```

It reports the event kinds no agent has actually reported, the rules that failed to load with
their reasons, and the hosts that have dropped events — before it reports what is covered. A
technique having a rule does not mean every way of performing that technique is detected; ATT&CK
techniques are broad and a rule covers a behaviour.

The console renders the same thing under **Detection**, in the same order, and deliberately without
a coverage percentage: ATT&CK has no denominator that would make one honest, and a percentage is
where a blind spot disappears into a rounding error. The cell worth looking at first is an event
kind with rules and no sensor reporting it — those rules are loaded, and they cannot fire. Viewers
can read the page; the forwarding section is admin-only, because destination addresses are part of
your infrastructure map.

### Dropped events

The agent's event buffer drops rather than blocking. That is deliberate: if it applied
backpressure, a slow server would become a slow host, and a sensor that destabilises the host gets
uninstalled — at which point coverage is zero rather than degraded.

Drops are **counted**, logged, written to the ledger and shown per host in the coverage view. A
pipeline that drops silently produces a clean console during exactly the incident that overwhelmed
it. If you see drops, the fix is usually fewer, more specific rules rather than a bigger buffer.

---

## Forwarding — DefendSec is not a SIEM

A behavioural sensor produces thousands of events a second. Storing them all would make DefendSec
a log lake: a different product, with a storage bill you are already paying somewhere else.

So DefendSec keeps a **short window** — a few hundred events per host, enough to answer "what else
was this host doing just before" on an alert — and forwards everything to the platform you already
run.

```bash
# /etc/defendsec/apid.env
DEFENDSEC_FORWARD='syslog=tcp://collector:514,webhook=https://siem.example/ingest#TOKEN'
```

| Kind | Form | Notes |
| --- | --- | --- |
| `syslog` | `tcp://host:514`, `tls://host:6514`, `udp://host:514` | RFC 5424, `local0`, JSON payload, RFC 6587 octet framing. TCP by default — UDP discards silently under load, which is the wrong property for a security record |
| `webhook` | `https://host/path#token` | Batched JSON POST; the token is sent as a bearer credential |
| `file` | `/var/log/defendsec-events.jsonl` | JSON lines. Useful for proving the pipeline before pointing it at a collector, and for air-gapped hosts |

OpenTelemetry is **not implemented**, and configuring `otlp=` is an error rather than a silent
no-op. An almost-OTLP exporter a collector rejects is worse than none; syslog and webhook both
reach an OTel collector today.

**Forwarding is lossy on purpose.** A collector that stops accepting connections must not stop
DefendSec matching rules or raising alerts — a tool that stops defending because its log shipper
is unhappy has its priorities backwards. Drops and delivery failures are counted:

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/detection/forwarding
```

Every alert is forwarded, not only behavioural ones: for many operators the collector is the
system of record, and a finding that exists only in DefendSec is one their process will not see.

---

## Configuration checks

Agents evaluate the packs in `packs/sca/` on every inventory cycle. Seven check types:

| Type | Checks | Runs a process? |
| --- | --- | --- |
| `file_regex` | A pattern in a config file, with drop-in support | No |
| `file_mode` | Permission bits and ownership | No |
| `mount_option` | Mount options on a filesystem | No |
| `sysctl` | A kernel parameter, read from `/proc/sys` | No |
| `package` | A package installed or absent | Fixed argv |
| `systemd_unit` | A unit enabled and/or active | Fixed argv |
| `command` | Output or exit status of an allowlisted command | Yes |
| `inventory_field` | A field in the host snapshot (evaluated server-side) | No |

`file_mode` compares as a **maximum**, not an equality: benchmarks say "no more permissive than
0644", and an exact match would fail a correctly-hardened host and teach operators to ignore the
result.

### A pack is code

`command` makes a data file executable, so it is deliberately narrow:

- **argv, never a shell string.** There is no `sh -c`, so nothing in an argument can become
  syntax — no globbing, no pipelines, no substitution, no quoting bug that turns a filename into a
  second command.
- **An allowlist of executables**, defaulting to read-only introspection tools. No shell, no
  interpreter, nothing that writes. A pack naming anything else **fails to load**.
- **Resolved from fixed directories**, so a writable directory earlier in `PATH` cannot substitute
  the binary.
- **A 10-second timeout and a 256 KiB output cap.**

This is a reduction in blast radius, not a sandbox. Adding a shell to the allowlist removes most
of it. The other six types need no arbitrary execution at all, which is why they were implemented
natively rather than as `command` wrappers.

### Writing a pack

A pack that will not load is refused outright rather than partially applied — a half-loaded pack
reports a clean result for checks that never ran, which reads as compliance. Refused at load:

- an unknown or missing check type
- a duplicate check id
- a check missing the fields its type needs
- a malformed regular expression or a non-octal `max_mode`
- a `command` naming an executable outside the allowlist
- **a control identifier not in the catalog** — a well-formed tag for a control that does not
  exist is the failure hardest to notice: the pack looks tagged and the compliance view never
  shows it

```yaml
- id: cis-5.1-shadow-permissions
  controls: [cis-v8:5.1, nist-800-53:AC-3, nist-800-53:IA-5]
  title: /etc/shadow is not readable by group or other
  severity: high
  type: file_mode
  path: /etc/shadow
  max_mode: "0640"
  owner: root
```

### Coverage, with its denominator

```bash
curl -sS -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  http://127.0.0.1:47264/v1/controls/check-coverage
```

It reports what ships, per pack and per type, and says plainly that this is **not** a benchmark. A
CIS Linux Benchmark is 150–400 checks per platform and DefendSec ships a few dozen; it is not a
certified benchmark scanner and does not claim to be. No percentage is reported — a percentage is
where a control nobody checked disappears into a rounding error.

Read it alongside `/v1/controls`, which states per control what DefendSec can and cannot evidence.

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

---

## AI agents — read freely, propose, never act

DefendSec can be driven by an AI agent over [MCP](https://modelcontextprotocol.io). The pitch is
not "AI-powered security": it is that **DefendSec is the enforcement layer that makes AI-initiated
response safe and provable.** An agent connected here cannot exceed the bounded command set, cannot
bypass the policy engine, cannot sign its own authority, and cannot act without leaving a
cryptographic record.

**DefendSec does not call a model.** It is an MCP *server*. Your agent runs wherever you run it and
connects inward. There is no API key to configure, no outbound dependency on any AI service, and no
path by which fleet data leaves the box to a model provider.

### Turning it on

Off by default — an MCP endpoint is a control surface, and one listening by default is an attack
surface you did not ask for.

```bash
# /etc/defendsec/apid.env
DEFENDSEC_MCP_ADDR=127.0.0.1:47266
# Only needed if a browser-based client will connect. Non-browser clients send
# no Origin and need no entry here.
DEFENDSEC_MCP_ORIGINS=https://console.example
```

It needs a configured database, because agent principals live there. It gets its own listener
rather than a path on the admin API so you can bind, firewall and log it separately — an agent
often runs somewhere the admin port deliberately is not reachable from.

### Registering an agent

```bash
curl -sS -X POST -H "Authorization: Bearer $DEFENDSEC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"triage","model":"some-model-v1","description":"alert triage"}' \
  http://127.0.0.1:47264/v1/agents
```

The token comes back **once** and is not recoverable: only its hash is stored, so a database copy
yields no working credential. The `model` field is required — the audit value of all this is being
able to answer "what recommended this action", and an agent with no declared model makes that
unanswerable from the start. It is self-reported, and the ledger says so rather than implying an
attestation DefendSec cannot make.

Revoke with `DELETE /v1/agents?name=triage`. The record is kept rather than deleted, so the ledger
still shows the principal existed and when it was withdrawn.

### An agent is not a user

Agent principals are a separate table, not a role on accounts. This matters more than it sounds:

- An agent token presented to the admin API resolves to **no caller at all**, not to an
  under-privileged one. There is no code path by which an agent becomes an admin.
- An agent cannot log into the console.
- Policy rules can name agents — `roles: [agent]` — so what an agent may propose is yours to
  configure, separately from what your operators may do.

### What policy needs to say

**Deny-by-default extends to the AI.** A policy permitting your admins and saying nothing about
agents permits an agent nothing. To let one propose, say so:

```yaml
rules:
  - id: agents-may-propose-containment
    effect: permit
    roles: [agent]
    commands: [live_query, isolate, quarantine_path]
```

`run_script` and `agent_update` are not proposable at all, whatever your policy says. The first is
arbitrary code; the second replaces the agent that enforces everything else.

### The proposal path

1. The agent calls `defendsec.propose_response` with a command type, a target, its reasoning, and
   the record ids it relied on.
2. Policy is evaluated **immediately**, as role `agent`. A refusal names the rule that decided and
   nothing is recorded as pending.
3. If permitted, the proposal is written **unsigned** to the approval queue with at least one human
   approval required — even where the policy would have let a human act with no approval at all.
4. An operator reviews it and approves. Only then is a command signed.

Three properties worth knowing because they are load-bearing:

- **The agent's own approval does not count.** A human requester self-approves; an agent does not.
  Otherwise a one-approval rule would let an AI act unsupervised.
- **Approval does not promote the request.** An approved proposal is re-evaluated as role `agent`,
  not as the approving admin — so a rule written to bound agents still binds at signing time. If
  approval promoted it, clicking approve would walk the proposal past the very rule meant to
  constrain it.
- **Break-glass does not widen it.** An emergency bypass is a human declaring an emergency. It does
  not extend what an agent may propose.

### What the ledger records

Every proposal, permitted or denied, lands in the hash-chained audit log with the proposing agent,
its declared model, its reasoning verbatim, the evidence it cited, and the prompt it says it was
given — alongside the approving human once one approves. That is what lets an auditor reconstruct
not just what was done, but what recommended it.

`defendsec verify` validates the whole chain, proposals included.

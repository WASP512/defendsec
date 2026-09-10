# DefendSec next phases (detailed plan)

**Product intent:** Free, self-hosted **Fleet-like agent console** (inventory, policies, live query, enroll, agent lifecycle) with **Wazuh-like host detection/response** (FIM, SCA, vulns, alerts, signed active response).

**Not in scope (the wall):** MDM wipe/lock/DEP/profiles/CSP, full kernel EDR, multi-tenant SaaS, replacing a SIEM log lake.

**Current baseline (shipped through Phase 6):**
- Console: Fleet, Hosts, Advisories, Patches, Versions, Integrity, Policies, Audit, Enroll, Scope
- Transport: Python HTTP agent + Go mTLS `defendsec-apid` / `defendsec-agentd`
- Signed commands: `isolate`, `release`, `kill_process`, `live_query`, `agent_update` (stage only)
- Optional Postgres dual-write (`db/migrations`, `internal/storepg`)
- Scripts: `scripts/ingest-osv.py`, `scripts/backup.sh`, `scripts/restore.sh`

**Suggested sequence:** Phase 7 → 8 → 9 → 10 → 11

Each phase below is a shippable slice with acceptance criteria. Prefer extending existing packages (`internal/control`, `internal/agentcmd`, `lib/*`, `app/(console)/*`) over new platforms.

---

## Cross-cutting design rules

1. **JSON remains usable without Postgres.** Postgres is durable dual-write / query path when `DATABASE_URL` / `DEFENDSEC_DATABASE_URL` is set.
2. **All host mutation stays Ed25519-signed** via apid → agent stream. No unsigned control.
3. **Alerts are first-class** starting Phase 7; findings/advisories triage can feed alerts but should not remain the only inbox.
4. **Default response is human-approved.** Auto-response, if added later, is opt-in and audited.
5. **Linux-first** for isolate/FIM depth; macOS/Windows keep inventory + flag-mode response until explicit parity work.
6. **No MDM features** even if “easy.” If a request looks like wipe/lock/profile, document under Scope and refuse in product UI.

### Shared identity model (introduce in Phase 7, reuse later)

```text
Alert
  id, createdAt, updatedAt
  deviceId, hostname
  kind: fim | sca | vuln | response | system
  severity: critical | high | medium | low | info
  title, summary
  status: open | acknowledged | resolved | suppressed
  sourceRef: { type, id }          # fim event id, check id, advisory id, command id
  detail: object                   # kind-specific payload
```

Persist:
- Postgres: new `alerts` table (+ indexes on `status`, `created_at`, `device_id`, `kind`)
- JSON fallback: `data/defendsec.json` → `alerts: Alert[]` (cap/rotate, e.g. 5k)

---

## Phase 7 — Detection core (Wazuh-shaped)

### Goal
A single **Alerts** inbox fed by richer FIM and SCA failures, so DefendSec feels like host detection—not only inventory.

### Why this first
Fleet-like inventory already exists. The biggest product gap vs Wazuh free is **triageable detections**.

### Workstreams

#### 7.1 Alert store + API + console
**Backend**
- Migration `db/migrations/002_alerts.sql`: `alerts` table, indexes
- `internal/storepg`: `InsertAlert`, `ListAlerts`, `UpdateAlertStatus`
- Dual-write helpers from control plane when FIM/SCA/vuln events occur
- Admin routes on `:47264`:
  - `GET /v1/alerts?status=&kind=&deviceId=&limit=`
  - `POST /v1/alerts/{id}/status` `{ status }`
- Next.js:
  - `app/api/alerts/route.ts`, `app/api/alerts/[id]/route.ts`
  - Page `app/(console)/alerts/page.tsx`
  - Nav entry in `components/app-shell.tsx`
  - Host detail: “Open alerts” strip

**UI behaviors**
- Filters: status, severity, kind, host
- Actions: acknowledge / resolve / reopen
- Empty, loading, error states
- Link-through to host + source (integrity row, policy check, advisory)

#### 7.2 Richer FIM events
**Today:** hash list + drift on Integrity; fsnotify triggers inventory (`internal/agentfim`).

**Target event shape**
```text
FimEvent
  id, deviceId, path
  previousHash, currentHash
  action: created | modified | deleted | permission_changed (best-effort)
  detectedAt
  severity (path-class default)
  processName?, processPid?   # best-effort; omit if unavailable
```

**Agent (`defendsec-agentd` + `internal/agentfim` / `hostinv`)**
- Emit structured FIM events on watch callback (not only “re-hash everything”)
- Support recursive directory watches with depth cap (config: `DEFENDSEC_FIM_PATHS`, optional `DEFENDSEC_FIM_RECURSIVE=1`)
- Per-path severity defaults (e.g. `sshd_config` high, `hosts` medium)
- Suppressions: unchanged hash after churn window; optional path glob ignore list

**Control plane**
- Persist events (JSON `fimEvents` + Postgres `fim_events` — extend columns as needed)
- On new FIM event → create/update Alert (`kind=fim`)

**Console**
- Integrity page: event timeline (not only current vs baseline)
- Host page: recent FIM alerts

#### 7.3 SCA packs (config assessment)
**Pack format** (versioned files under `packs/sca/`):
```yaml
id: sca-linux-ssh-v1
name: Linux SSH baseline
platform: linux
checks:
  - id: sshd-password-auth
    title: PasswordAuthentication should be no
    severity: high
    type: file_regex
    path: /etc/ssh/sshd_config
    must_match: '(?i)^PasswordAuthentication\s+no'
  - id: firewall-enabled
    title: Host firewall reported enabled
    severity: medium
    type: inventory_field
    field: firewall
    expect: true
```

**Check types (Phase 7 set)**
- `file_regex` / `file_absent` / `file_mode` (Unix)
- `inventory_field` (reuse agent inventory booleans/fields)
- `pkg_absent` / `pkg_min_version` (light; fuller vulns in Phase 9)

**Runtime**
- Agent evaluates packs shipped in-repo (embedded or downloaded later)
- Report `ScaResult[]` on inventory or dedicated gRPC/report field
- Control plane stores latest results per device; failing checks → Alerts (`kind=sca`)

**Console**
- Policies page gains “SCA” section or dedicated `/sca` page listing pack results by host
- Host detail: pass/fail checklist

### Phase 7 deliverables
| Area | Deliverable |
| --- | --- |
| Schema | `alerts` (+ FIM column extensions if needed) |
| Agent | Structured FIM events; SCA evaluator for v1 packs |
| Apid | Alert APIs; alert creation hooks |
| Console | `/alerts`, Integrity timeline, SCA results |
| Packs | ≥1 Linux SSH/host hardening pack (≥8 checks) |

### Acceptance criteria
1. Changing a watched file creates a FIM alert visible in `/alerts` within one debounce window.
2. Operator can ack/resolve an alert; status persists across refresh (Postgres or JSON).
3. At least one SCA pack runs on Linux agent and failing checks appear as alerts.
4. No MDM UI or APIs added.
5. `go test ./...` and existing npm advisory tests pass; manual check of `/alerts` on desktop + mobile layout.

### Risks / mitigations
- **FIM noise** → defaults to small path set; ignore globs; severity defaults; baseline still authoritative for “drift vs accepted.”
- **SCA false positives** → packs versioned; checks can be severity `info`; ack without claiming “fixed.”

### Explicit non-goals for Phase 7
- osquery parity, agent binary apply, NVD full mirror, auto-isolate on alert

---

## Phase 8 — Fleet-like query & agent ops

### Goal
Make day-2 operations feel like free Fleet: broader live query, saved queries, real agent updates, cleaner enroll/cert lifecycle.

### Workstreams

#### 8.1 Live query expansion
**Today:** allowlist `processes`, `listening_ports`, `users`, `os_info` in `internal/agentcmd/live.go`; results mostly in command ack text; `live_query_results` table unused.

**Add tables (Linux-first, best-effort elsewhere)**
- `processes` (enrich: user, cmdline truncated)
- `listening_ports` (enrich: pid/process if available)
- `users`, `logged_in_users`
- `crontab`, `systemd_units` (enabled/running subset)
- `mounts`, `kernel_modules` (optional, capped)
- `os_info` (keep)

**Hardening**
- Keep allowlist (no arbitrary shell)
- Caps: row limits, cmdline length, timeout
- Persist results via `storepg.SaveLiveQueryResult` + JSON command log
- Console: result panel with tabular view + history on host page

#### 8.2 Saved queries
- Store saved query defs in JSON/Postgres (`id`, `name`, `query`, `createdAt`)
- UI: save from host query runner; run saved query against one host (fleet fan-out later in 8.x or 11)
- Admin API: `GET/POST /v1/saved-queries`

#### 8.3 Agent update apply (finish Phase 6 staging)
**Today:** `agent_update` writes `pending-update.json` only; releases via `/v1/agent-releases`.

**Target flow**
1. Operator publishes release metadata (url, version, sha256, channel, notes)
2. Console/host action sends signed `agent_update`
3. Agent downloads to temp path, verifies sha256, replaces binary atomically, restarts under systemd/launchd when managed
4. On failure: leave old binary, alert `kind=system`, ack error

**Also**
- Console UI for “Push agent update” on host (missing today)
- Version inventory field already on hello/heartbeat — surface outdated agents on Fleet

#### 8.4 Enrollment / cert lifecycle polish
- Document + implement **rotate**: revoke fingerprint → agent re-enroll path
- UI: revoke button on host (calls existing `/v1/revoke`) + clear guidance
- Prevent silent orphan presence rows after revoke

### Phase 8 deliverables
| Area | Deliverable |
| --- | --- |
| Agent | Expanded live queries; update apply with hash verify |
| Apid | saved queries; live query result persistence |
| Console | Query results UI; push update; revoke control |
| Docs | Agent update + revoke/re-enroll runbook section in README |

### Acceptance criteria
1. Live query `processes` and `listening_ports` return structured results shown in UI (not only a string blob).
2. Results stored and viewable after navigation away/back (DB or file).
3. Staged update with matching sha256 applies on Linux test host; mismatched sha256 refuses and alerts.
4. Revoke disconnects agent; re-enroll with secret creates new cert and host presence.

### Risks / mitigations
- **Self-update bricking** → verify hash, keep previous binary `.bak`, require systemd `Restart=` for managed installs; document manual recovery.
- **Query abuse** → allowlist + caps only; never `shell` query type.

### Non-goals
- Full osquery SQL dialect
- Fleet “teams” multi-tenancy
- Automatic silent upgrades without operator action

---

## Phase 9 — Vulnerability pipeline

### Goal
Turn inventory into durable, scheduled vuln findings (Fleet/Wazuh ordinary vuln workflows)—not a one-off script.

### Workstreams

#### 9.1 Ingest service/job
- Evolve `scripts/ingest-osv.py` into a schedulable job:
  - Input: distinct package names from fleet inventory (Postgres or JSON)
  - Ecosystem hints: Debian/Ubuntu/Alpine/RPM/Go where detectable
  - Upsert into `advisories` with `source=osv`, timestamps
- Optional Phase 9.1b: NVD supplemental for CVE metadata (not required to ship 9.1)
- Document cron/systemd timer example

#### 9.2 Matching engine improvements
- Keep `lib/advisories.ts` matching for console; share rules with any Go matcher used at ingest time if needed
- Distro epoch / revision handling (already partial for Debian epochs)
- Status: open finding when installed < fixed; auto-resolve when inventory shows patched

#### 9.3 Findings ↔ Alerts
- Create/update Alert `kind=vuln` for new high/critical matches
- Advisories page remains catalog; Alerts is triage inbox
- Host page: open vuln alerts count

#### 9.4 Operator workflow
- Bulk ack by advisory id or severity
- “Last ingest at” metadata in UI (`meta` table / JSON)

### Acceptance criteria
1. Timer/job refresh updates advisories without manual paste.
2. Installing a vulnerable package (or fixture) opens a vuln alert; upgrading clears/resolves it on next inventory.
3. Ingest failure is visible (audit + UI banner/meta), does not corrupt catalog.

### Risks
- Version compare false positives/negatives across ecosystems → start with Debian/Ubuntu accuracy bar; mark others experimental in UI.

### Non-goals
- Commercial vuln feed feature-parity
- Exploitability scoring / EPSS as a blocker (optional later)

---

## Phase 10 — Active response pack

### Goal
Wazuh-like **signed** active response library, still operator-driven by default.

### Workstreams

#### 10.1 Response catalog
Signed command types (extend carefully):
| Type | Effect |
| --- | --- |
| `isolate` / `release` | Existing; harden Linux iptables chain + better status |
| `kill_process` | Existing |
| `run_script` | Allowlisted script id only (scripts shipped with agent) |
| `quarantine_path` | chmod/move watched file to quarantine dir (Linux) |

**No arbitrary remote shell.**

#### 10.2 Playbooks (suggest, don’t auto-run by default)
- Map alert kinds → suggested responses (UI buttons)
- Example: critical FIM on `sshd_config` → suggest isolate + show diff
- Optional later flag: `DEFENDSEC_AUTORESPONSE=1` per host (off by default)

#### 10.3 Audit + alerts
- Every response creates `audit_log` + Alert `kind=response` (info/high depending on action)
- Command result history already partially in `commands` — link from alert `sourceRef`

#### 10.4 OS notes
- Linux: net isolate supported when root + env flag
- macOS/Windows: keep flag-mode; document limitations on Scope page

### Acceptance criteria
1. From an alert, operator can launch a suggested signed response and see ack + audit entry.
2. `run_script` rejects unknown script ids.
3. Isolate/release still works; failed net isolate still sets flag and reports error clearly.

### Non-goals
- SOAR engine, mass auto-isolation fleets without confirmation UX

---

## Phase 11 — Production ops (still not MDM)

### Goal
Run DefendSec for a real org fleet with boring reliability—not feature sprawl.

### Workstreams
1. **RBAC:** viewer vs operator vs admin (signed commands restricted)
2. **Console TLS** deployment docs (Caddy/nginx) + secure cookie notes
3. **Migrations** tooling/docs; backup/restore drill checklist (scripts exist)
4. **Packaging:** real systemd unit + package artifacts; launchd; Windows service sketch → MSI later
5. **CA rotation runbook:** revoke, re-enroll, leftover presence cleanup
6. **Scale notes:** indexes, presence compaction, alert retention, apid memory
7. **Webhook egress (optional):** push high/critical alerts to Slack/HTTP

### Acceptance criteria
1. Fresh install docs: compose Postgres + apid + console + one agent, 15-minute path.
2. Backup/restore drill restores devices, alerts, and PKI on a clean VM.
3. Viewer cannot issue isolate; operator can; all attempts audited.

---

## Milestone map (what “done” feels like)

| After phase | Operator experience |
| --- | --- |
| **7** | “I have an Alerts inbox with FIM + SCA like a small Wazuh.” |
| **8** | “I can query hosts and upgrade agents like free Fleet.” |
| **9** | “CVEs refresh and track to fix without babysitting JSON.” |
| **10** | “I can respond from an alert with signed actions.” |
| **11** | “I can hand this to another admin with a runbook.” |

---

## Implementation notes (repo anchors)

| Concern | Primary anchors |
| --- | --- |
| Admin HTTP | `cmd/defendsec-apid`, `internal/control/admin.go`, `commands.go`, `server.go` |
| Agent commands | `cmd/defendsec-agentd/commands.go`, `internal/agentcmd/*` |
| FIM watch | `internal/agentfim`, `internal/hostinv/collect.go` |
| Presence / inventory merge | `internal/presence`, `lib/mtls-agents.ts`, `lib/store.ts` |
| Advisories | `lib/advisories.ts`, `scripts/ingest-osv.py`, `advisories` table |
| Console shell | `components/app-shell.tsx`, `app/(console)/*` |
| Command proxy | `app/api/devices/[id]/command/route.ts` |
| Postgres | `db/migrations/*`, `internal/storepg`, `internal/db`, `lib/pg.ts` |

---

## Testing strategy per phase

1. **Go unit tests** for parsers, SCA check eval, update hash verify, query allowlist rejects
2. **Integration (local):** apid + agentd + Postgres; issue commands; assert DB rows
3. **Console:** critical paths via browser (alerts triage, query results, update button)
4. **Regression:** existing signed isolate/kill + inventory still green
5. **Noise test (Phase 7):** touch watched file N times; ensure debounce doesn’t flood inbox unbounded

---

## Recommended immediate next slice (Phase 7.0)

Smallest vertical that proves the direction:

1. `alerts` schema + store + `/alerts` page (read/ack)
2. Create alerts from existing FIM drift path (no new agent protocol yet)
3. Add one SCA pack evaluated server-side from latest inventory fields / known config facts where possible; agent-side file_regex checks next

Then proceed 7.2 structured FIM events + 7.3 full agent SCA.

---

## Decision log (locked unless revisited)

- Fleet-like + Wazuh-like: **yes**
- Full MDM: **no**
- Postgres optional: **yes**
- Unsigned agent control: **no**
- Arbitrary remote shell: **no**
- Auto-response default on: **no**

# DefendSec — direction

Status: **live**. Decided 2026-10-23. This file replaces the plan in [ROADMAP.md](ROADMAP.md),
which is now a historical record of the EDR phase.

## The decision

**DefendSec is not an EDR.** Mason Hargrove decided on 2026-10-23 that DefendSec stops trying to
be an endpoint detection-and-response product and becomes a **proactive exposure-management tool
for small fleets and MSP clients**.

The detection and response code (sensors, Sigma rules, process telemetry, host isolation, signed
response commands, playbooks, the policy engine, the MCP agent interface) **is being removed**,
not parked.

Why, as far as this repository can show:

- The decision is a product-scope call: the tool is for finding and tracking exposure, not for
  catching or stopping an attacker.
- The other half of DefendSec is the one a small fleet or an MSP can show a client each month:
  inventory, posture checks, a tamper-evident ledger and evidence that verifies offline.
- Detection and response is also the larger and riskier code. The slice 0 baseline counts about
  14,000 lines of Go (source plus tests) in the drop-list packages alone, and none of it has been
  run against a real intrusion. See [VERIFIED.md](VERIFIED.md).

Removing code happens in a fixed order, described under [Slice plan](#slice-plan).

## What the product is

One DefendSec instance per client (or per small fleet). It answers five questions continuously.

| # | Question | How it is answered |
| --- | --- | --- |
| 1 | **What is exploitable right now?** | Installed software matched against advisories, ranked **CISA KEV → EPSS → CVSS**, with the **distro's own fixed version** (a package patched by the distro is not a finding) |
| 2 | **What is end-of-life or unpatched?** | Supported-OS policy, pending patches by age, hosts that have stopped reporting, and application software from third-party repositories that its upstream no longer patches ([EOL.md](EOL.md)) |
| 3 | **What is misconfigured?** | The SCA engine and its control-tagged check packs |
| 4 | **What is exposed from the outside?** | DNS, MX, SPF, DKIM, DMARC, MTA-STS, certificate expiry and open ports, scanned from outside |
| 5 | **Is it getting better?** | Audit periods, a hash-chained ledger and evidence exports that verify offline |

The deliverable per client is:

1. a ranked **"fix these this week"** list,
2. a **trendline** showing the count of open findings over time, and
3. a **signed export** proving a finding was open on date A and closed on date B.

### What it is not

- **Not an EDR.** It does not detect intrusions and does not respond to them.
- **Not MDM.** No remote wipe, lock or configuration profiles.
- **Not a SIEM.** It does not ingest or search logs.
- **Not a patch deployer.** It reports what is missing and how old it is; it does not install
  anything.
- **Not a SaaS.** It runs on your hardware, one instance per client, and works without a vendor
  cloud. (Public vulnerability feeds are fetched in bulk. Nothing about your hosts leaves.)

## What is kept

| Concern | Where it lives |
| --- | --- |
| Control plane (admin API, agent gRPC) | `cmd/defendsec-apid`, `internal/control` |
| TLS front proxy | `cmd/defendsec-web`, `internal/webtls` |
| Offline evidence verifier | `cmd/defendsec-verify`, `internal/evidence`, `internal/auditchain`, `internal/anchor` |
| Inventory collection (hardware, OS, software, pending patches) | `internal/hostinv`, `cmd/defendsec-agentd` |
| Version comparison (dpkg, rpm) and matching | `internal/vuln` |
| SCA engine and packs (42 checks) | `internal/sca`, `packs/sca/*.yaml` |
| Control catalog, audit periods, exceptions | `internal/controls`, `internal/auditlayer` |
| Users, TOTP, OIDC | `internal/identity`, `internal/sso` |
| Postgres store and migrations | `internal/storepg`, `internal/db`, `db/migrations` |
| Console (Next.js) | `app/(console)/*`, `app/api/*`, `components/`, `lib/` |
| Packaging (Proxmox LXC, systemd, Ansible, Terraform) | `packaging/` |

## What is replaced

- **The advisory catalog and matcher.** The console matcher (`lib/advisories.ts`) held a
  hard-coded catalog, and the `advisories` table had one version floor per row with no distro
  dimension. The catalog and the client-side matcher are deleted (slice 4); findings are
  computed by the control plane against distro-specific fixed versions (see
  [MATCHING.md](MATCHING.md)).
- **The OSV ingest script** (`scripts/ingest-osv.py` and its systemd timer), replaced by the feed
  sync service `defendsec-feeds` in slice 3 (see [FEEDS.md](FEEDS.md)). The script is deleted: it
  sent the fleet's package names to a third party.

## What is removed

Removed in slice 6, after the feed pipeline and matcher are merged (see rule 4 below):

- Go packages `internal/{sensor,events,sigma,proclist,playbook,policy,mcp,triage,etw,forward}`
- `packs/sigma`
- `cmd/defendsec-loadtest` and `scripts/test-isolation-netns.sh`
- The Windows service, MSI and ETW sensor
- Console pages Detection, Response and Proposals
- Command types `isolate`, `release`, `kill_process`, `quarantine_path`, `run_script`

Until slice 6 lands, this code is still in the tree and still builds. It is not maintained and
not promoted, and new work on it is out of scope.

## Feed sources

Feeds are fetched in **bulk or from mirrors**, never per-package live queries. Each fetch is
recorded in a `feed_snapshots` row (URL, fetch time, SHA-256), and every finding references the
snapshot it was derived from. That reference is what makes a finding reproducible.

| Source | URL |
| --- | --- |
| Ubuntu OVAL | `https://security-metadata.canonical.com/oval/com.ubuntu.<release>.usn.oval.xml.bz2` |
| Debian security tracker | `https://security-tracker.debian.org/tracker/data/json` |
| Red Hat OVAL v2 (RHEL 8/9/10) | `https://security.access.redhat.com/data/oval/v2/` |
| AlmaLinux / Rocky | each publishes its own OVAL / errata |
| SUSE OVAL | `https://ftp.suse.com/pub/projects/security/oval/` |
| OSV bulk | `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip` |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| EPSS | `https://epss.cyentia.com/epss_scores-current.csv.gz` |
| endoflife.date (application release calendar, API v1) | `https://endoflife.date/api/v1/products/full` |

## Rules of engagement

1. **No detection or response work.** Sensors, Sigma, process lineage, isolate/kill/quarantine,
   playbooks, autonomous response and MCP proposals are out of scope. A task that drifts there
   stops.
2. **"Works" means a real run.** A claim cites the command and its output. "Compiles" and "tests
   pass" are stated as exactly that. [VERIFIED.md](VERIFIED.md) records what was run, where, and
   what happened. Anything not listed there has not been verified.
3. **Branches and pull requests only.** Branches are named `scout/<slice>-<topic>`. Nothing is
   pushed to `main`, nothing is force-pushed, no shared history is rewritten.
4. **Phase 0 before deletions.** The feed pipeline and the distro-aware matcher (slices 2–4)
   merge before any EDR code is removed. Before the first deletion, the branch
   `archive/action-governance` is pushed, holding `internal/{policy,sign,mcp}` and the
   two-person-approval code exactly as they are today, so the work is recoverable.
5. **No secrets and no client data** in commits, issues, pull requests or chat: no API keys, no
   fleet inventories, no hostnames of client machines.

## Slice plan

Each slice ends with a pull request, the commands that were run and their results, a statement of
what is **not** verified, and what is needed next.

| Slice | Content | Done when |
| ---: | --- | --- |
| 0 | **Baseline.** Build, vet and test on a clean host; record the result | [VERIFIED.md](VERIFIED.md) has exit codes and counts |
| 1 | **Direction.** This document, README reframe, ROADMAP banner, LICENSE (AGPL-3.0) | Merged |
| 2 | **Advisory schema.** Distro dimension; fixed-version per release and stream; `feed_snapshots` | Migration applies and rolls forward on Postgres |
| 3 | **Feed sync service.** Bulk fetch of the sources above, snapshot rows with SHA-256, KEV and EPSS enrichment | A real run fetches and records every feed |
| 4 | **Distro-aware matcher.** Uses the dpkg and rpm comparators and the distro's fixed versions | **Zero findings on a fully patched Ubuntu 22.04 and a fully patched Rocky 9** |
| 5 | **Exposure view.** The ranked "fix these this week" list, the trendline | Console shows KEV → EPSS → CVSS ranking from real data |
| 6 | **Remove the EDR.** Archive branch first, then delete (see "What is removed") | Build, vet, tests and console build are green with the code gone |
| 7 | **External surface scanner.** DNS, mail authentication, certificate expiry, open ports | A real scan of a test domain, results in the console |
| 8 | **Datto RMM collector.** Inventory collected from Datto RMM | A real run against a test account |
| 9 | **v0.1.0 release, verified.** Reproducible build, SBOM, signed checksums, VERIFIED.md complete | Release artifacts verify with `scripts/verify-release.sh` |

Slices 2 through 4 are **Phase 0**. Until slice 4 is done, DefendSec does not have a trustworthy
vulnerability answer, and the README says so.

## Approved additions (2026-10-23)

Mason approved five slices after the plan above was written. They keep the product's shape (agentless or read-only,
one instance per client, findings that rank into "Fix this week" and close with evidence) and none of them is
detection or response. Slice 8 (the Datto RMM collector) is already in the plan.

| Slice | Content | Owner | Done when |
| ---: | --- | --- | --- |
| 10 | **Application end-of-life.** Software from third-party repositories (Sury PHP, PGDG, NodeSource, ...) checked against endoflife.date through the feed pipeline. The distribution's own packages are never judged: they follow the distribution's lifecycle. See [EOL.md](EOL.md) | scout | A third-party PHP 8.0 host gives one finding naming PHP 8.0 and 2023-11-26; patched Ubuntu and Rocky hosts give none |
| 11 | **Repository health.** Expired repository keys and stale package indexes, which hide pending updates. "Pending updates" are marked unreliable until the indexes are fresh | scout | A host with a stale index or an expired key is flagged and its pending-update count says it cannot be trusted |
| 12 | **Microsoft 365 identity posture.** MFA coverage, legacy authentication, admin roles, hiding and forwarding inbox rules (the business-email-compromise lesson) | lookout | A real read-only run against a tenant Mason creates the credentials for |
| 13 | **Google Workspace identity posture.** The same questions for Google Workspace | lookout | A real read-only run against a test domain |
| 14 | **Autotask tickets.** "Fix this week" items opened as tickets in the MSP's Autotask | lookout | A real ticket created from a real finding in a test queue |

Slices 12 to 14 need credentials the client or Mason creates; the engineer stops with click-by-click setup steps and the
run happens when the credentials exist. The order is 10, 11, EDR removal (6), release (9) for scout, and 7, 8, 12, 14,
13 for lookout.

## Open questions

- Whether Windows stays as an inventory source after the Windows service and MSI are removed
  (slice 8's RMM collector may cover it). No Windows agent code has ever been run on a real
  Windows machine.
- How the external scanner is kept in scope (for example, scanning only domains the operator has
  declared). To be decided in slice 7.
- Licence: AGPL-3.0 as of slice 1. Dependency licence compatibility has not been audited.

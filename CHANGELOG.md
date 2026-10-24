# Changelog

All notable changes to DefendSec are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, a minor version may change behaviour
that an operator relies on; the entry says so when it does.

What has and has not been run on a real host is not in this file. It is in
[docs/VERIFIED.md](docs/VERIFIED.md), and the release notes for each version
([docs/releases](docs/releases)) summarise it.

## [0.1.0] - 2026-10-24

The first release. It is the first version of DefendSec as an **exposure-management tool**: it
tells a small fleet or an MSP client what is exploitable, what is out of date, what is
misconfigured and what is exposed from the outside, and keeps evidence that it is getting better.
Everything below this line was built after the direction change of 2026-10-23
([docs/DIRECTION.md](docs/DIRECTION.md)); earlier history is the endpoint-detection-and-response
phase and is kept in [docs/ROADMAP.md](docs/ROADMAP.md) for the record.

### Changed

- **DefendSec is not an EDR.** It does not detect intrusions and does not respond to them. The
  product is one self-hosted instance per client that answers five questions: what is exploitable
  now, what is end-of-life or unpatched, what is misconfigured, what is exposed from outside, and
  whether it is getting better.
- The server installer installs a **published release** (prebuilt, checksummed binaries) instead
  of compiling from source. Building from source is still available with `--from-source`.
- `defendsec-update` (Operations → Updates) also replaces `defendsec-web` and `defendsec-feeds`,
  and restarts the HTTPS front end, not only `defendsec-apid` and the console.

### Added

- **Vulnerability feeds** (`defendsec-feeds`, a daily systemd timer): CISA KEV, EPSS, Ubuntu OVAL,
  Debian security tracker, Red Hat OVAL, Rocky (Apollo) and AlmaLinux errata, SUSE OVAL, the
  Microsoft Security Update Guide, and endoflife.date. Each feed is snapshotted with its SHA-256,
  guarded against a feed that shrinks suspiciously, and exportable as a **signed offline bundle**
  for air-gapped installs. Only whole public files are downloaded; nothing about your hosts is sent.
- **Distro-aware matching**: installed packages are compared (dpkg and rpm comparators, source
  packages, rpm epochs) with the *distribution's own* fixed version, so a backported fix is not a
  finding. Rocky and Alma hosts are matched against their own errata; a fix that only Red Hat has
  is `awaiting_vendor`, not a finding to act on. A host no feed covers is "not assessed", never
  "clean". ([docs/MATCHING.md](docs/MATCHING.md))
- **Exposure view**: findings ranked **KEV → EPSS → CVSS**, a **Fix this week** card on the Fleet
  page that counts only what can be fixed now, a separate watch list for findings with no fix (an
  exploited one there gets a red callout), and a trendline of open findings from when each was
  first seen and resolved. ([docs/EXPOSURE.md](docs/EXPOSURE.md))
- **Application end-of-life**: software installed from a third-party repository whose upstream has
  stopped patching it is a finding. Distribution packages are never judged. A Windows Supported
  OS policy is edition- and build-aware. ([docs/EOL.md](docs/EOL.md))
- **Repository health**: expired signing keys and stale package indexes on apt, dnf and zypper
  hosts. "Pending updates" is marked unreliable when the host's package cache is stale.
  ([docs/REPO_HEALTH.md](docs/REPO_HEALTH.md))
- **External surface scanner** (agentless): SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, CAA,
  dangling CNAMEs, certificate expiry and chain, legacy TLS and exposed ports on declared and
  authorised assets, with findings that rank next to vulnerabilities. A check that could not run
  is shown as not assessed. ([docs/SURFACE.md](docs/SURFACE.md))
- **Microsoft 365 identity posture** (read-only Graph): MFA registration, administrator MFA,
  legacy authentication, and inbox rules that hide mail or forward it outside the organisation.
  ([docs/M365.md](docs/M365.md))
- **Datto RMM collector** (read-only API, no new agent on Windows PCs): Windows inventory, patch
  status and missing KBs, mapped through the Microsoft feed to CVEs and KEV.
  ([docs/DATTO-RMM.md](docs/DATTO-RMM.md))
- **Autotask tickets** from Fix this week: one ticket per remediation action, idempotent, dry run
  first, every action in the audit ledger. ([docs/AUTOTASK.md](docs/AUTOTASK.md))
- **Evidence**: the signed evidence export now covers surface findings, and `defendsec-verify`
  fails a bundle whose findings were withheld, injected or edited. Bundles from before this
  release verify as "dates only" for those findings. `defendsec-verify` runs on Linux, macOS and
  Windows with no server, database or network.
- **Release supply chain**: reproducible Go builds (`scripts/check-reproducible.sh`), CycloneDX
  SBOMs for every binary and the console, a Sigstore keyless signature over `SHA256SUMS`, a GitHub
  provenance attestation published with the release (verifiable offline), and
  `scripts/verify-release.sh` that checks all of it. The release installers
  (`install-server.sh`, `create-proxmox-ct.sh`) are release assets, covered by `SHA256SUMS`.
- `defendsec-feeds` is installed and scheduled by the server installer. Before this release the
  installer did not install it, so a fresh server never matched anything.

### Removed

The detection and response half of the product. The last commit that contained it is kept on the
branch `archive/action-governance`.

- Endpoint sensors (eBPF, ETW), the event pipeline, process lineage, Sigma rules and their packs.
- Host response: isolate, release, kill process, quarantine path, run script. The server answers
  these command types with `400`.
- Playbooks, the policy engine, the triage workflow, break-glass approvals and the MCP agent
  interface.
- The Detection, Response and Proposals pages and their API routes.

What stays: `live_query` and `agent_update` (both off until `DEFENDSEC_ALLOW_COMMANDS` names
them), alert forwarding, file-integrity change events and the drift alert, and the Windows
inventory agent, service and MSI.

### Known limits

- The Windows agent, the Datto RMM collector, the Microsoft 365 collector and Autotask have **not
  been run against real Windows machines, accounts or tenants**. Fakes and fixtures only.
- A Rocky or Alma host can show a fixable finding for a fix that the errata feed has published but
  the mirrors do not carry yet. It clears when the mirror catches up.
- The external scanner has one vantage point.
- Alert forwarding does not carry the audit ledger, surface, Microsoft 365 or repository-health
  findings.
- `docs/ROADMAP.md` and the technical white paper still describe features that were removed.
- Pre-release agents that were isolated by the old response code need manual clean-up after an
  upgrade ([docs/OPERATIONS.md](docs/OPERATIONS.md)).

# DefendSec

**Exposure management for small fleets and MSP clients: what is exploitable, what is out of date,
what is misconfigured, what is exposed, and proof that it is getting better.**

DefendSec is self-hosted: one server per client, and one small agent per host. There is no vendor
cloud, no per-seat subscription, and nothing about your hosts leaves your network. It covers Linux
and Windows hosts. Public vulnerability feeds are meant to be fetched in bulk and can be mirrored;
see [Honest status](#honest-status) for where that stands today.

> **Direction change, 2026-10-23.** DefendSec is no longer an endpoint detection-and-response
> product. See
> [docs/DIRECTION.md](docs/DIRECTION.md) for what it is now, what is being removed, and the
> slice-by-slice plan. This README describes the product as it is **today** and marks what is not
> built yet.

## Why DefendSec exists

Small IT teams and MSPs are asked the same questions by clients, insurers and auditors, month
after month:

- *What on our network can be exploited right now, and what do we fix first?*
- *What is end-of-life or missing patches?*
- *Is anything misconfigured against the framework we are held to?*
- *What does the internet see of us?*
- *Is it getting better, and can you prove it?*

Enterprise vulnerability-management platforms answer these at enterprise prices, from someone
else's cloud. Open-source building blocks (OpenVAS, osquery, Wazuh, a spreadsheet) answer parts of
it, and assembling them into something you can defend to an auditor is a project in its own right.
Compliance frameworks (CIS, NIST 800-53 / 800-171, CMMC, CJIS) ask for *evidence*, not dashboards.

DefendSec is built around three ideas:

1. **You own it.** Everything runs on your hardware, including the audit log. One instance per
   client, no shared tenant.
2. **Every claim is checkable.** Configuration results carry their control IDs, and the audit
   ledger is hash-chained and can be anchored externally. Evidence bundles verify offline with a
   standalone tool. Release binaries are reproducible, signed and ship with SBOMs.
3. **It tells you what it can't see.** A check the host could not answer is reported as missing
   evidence, never as a pass or a failure. The docs state plainly what has and hasn't been
   verified ([docs/VERIFIED.md](docs/VERIFIED.md)).

### The deliverable

For each client: a ranked **"fix these this week"** list, a **trendline** of open findings, and a
**signed export** proving a finding was open on date A and closed on date B.

### Who it's for

- **MSPs and consultants** who want one self-hosted stack per client, not a shared SaaS tenant.
- **IT teams of one to twenty** who need to know what to patch first, without an enterprise
  contract.
- **Regulated and sensitive environments**: government, education, health, defense suppliers
  working toward CMMC, where data residency and audit evidence matter.

## What it does

The first column is the question DefendSec answers. The second is what exists **today**. The third
is what is **not built yet**.

| Question | Today | Not built yet |
| --- | --- | --- |
| **What is exploitable right now?** | The control plane matches each host's packages against its own distribution's advisories (fixed versions are the distro's, so a backported fix is not a finding; Rocky/Alma hosts are matched against their own errata) and ranks the result **KEV → EPSS → CVSS** on the Exposure page, with the reason each row is where it is, the hosts, installed against fixed version and the feed snapshot it came from. The Fleet page leads with a **Fix this week** card. Findings with no fix, or fixed upstream and awaiting Rocky/Alma, are a separate watch list; an exploited one there gets a red callout. `defendsec-feeds` syncs CISA KEV, EPSS and the distro advisories and both pages show how old they are ([docs/EXPOSURE.md](docs/EXPOSURE.md), [docs/MATCHING.md](docs/MATCHING.md), [docs/FEEDS.md](docs/FEEDS.md)) | Software installed outside the package manager on Linux. Only Ubuntu 22.04 and Rocky 9.8 have been matched on a real host ([VERIFIED.md](docs/VERIFIED.md)) |
| **What is end-of-life or unpatched?** | Hardware, OS, software and pending patches per host on Linux (apt, dnf/yum, zypper) and Windows (Windows Update). A **Supported OS** policy flags hosts on releases their vendor no longer patches. **Application end-of-life** (endoflife.date): software installed from a third-party repository (Sury PHP, PGDG, NodeSource, a PPA) whose upstream has stopped patching it is a finding in Fix this week, with the origin, the end-of-life date and the release to upgrade to; the distribution's own packages are never judged, they follow its lifecycle ([docs/EOL.md](docs/EOL.md)). **Repository health**: expired signing keys and stale package indexes on apt, dnf and zypper hosts, and "pending updates" marked unreliable when the host's package cache is stale ([docs/REPO_HEALTH.md](docs/REPO_HEALTH.md)) | Pending patches ranked by age; software installed outside the package manager on Linux |
| **What is misconfigured?** | 42 SCA checks in control-tagged packs. On Linux the CIS-aligned checks know each distro: its package names, SELinux on Fedora, RHEL and openSUSE, AppArmor on Ubuntu and Debian. On Windows: BitLocker, Defender, firewall, SMBv1, UAC and RDP. Firewall state is read from ufw, firewalld or plain nftables. A check the host cannot answer is reported as missing evidence | |
| **What is exposed from the outside?** | An external surface scanner: declared domains, hostnames and IPs (each confirmed as authorised to test) are checked daily and on demand for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, CAA, dangling CNAMEs, certificate expiry and chain, legacy TLS and exposed ports, on the Assets and Surface pages ([docs/SURFACE.md](docs/SURFACE.md)). A check that could not run is shown as not assessed, never as a pass. Surface findings rank in the weekly list next to vulnerabilities (critical and high above every non-KEV vulnerability: a judgement, see [docs/EXPOSURE.md](docs/EXPOSURE.md)), have a trend series and a Fleet card, and ride in the signed evidence export | One vantage point; scanning is not a pass for what it could not check |
| **Is it getting better?** | A trendline of open findings per day (with the KEV share and the nothing-to-install count) for 30/90/180 days or any audit period, computed from when each finding was first seen and resolved; how each finding closed (fixed, package removed, advisory changed) is recorded. Control mapping for NIST 800-53, 800-171, CIS v8, CMMC and CJIS; audit periods, documented exceptions, a hash-chained audit ledger and offline-verifiable evidence exports | The trendline starts at the first feed snapshot; earlier history was never recorded. The surface series starts with the first surface scan; surface scans stored before slice 7b are unattested in the evidence export |

Alongside that:

| Area | What you get |
| --- | --- |
| **File integrity** | Hash-based checks on sensitive paths, with baselines you accept explicitly. On Linux: account, SSH, sudo and crypto-policy files. On Windows: `hosts`, `services`, Group Policy scripts and scheduled tasks |
| **Accounts** | Named users, TOTP, lockout, OIDC single sign-on, and an audit ledger of every action |
| **Integrations** | Prometheus metrics, OpenTelemetry traces, an Ansible role and a Terraform module for rollout. Read-only collectors for **Datto RMM** (Windows inventory and patch status with no new agent, [docs/DATTO-RMM.md](docs/DATTO-RMM.md)) and **Microsoft 365** (MFA, legacy authentication, admin roles, hiding and forwarding inbox rules, [docs/M365.md](docs/M365.md)), and **Autotask** tickets from Fix this week ([docs/AUTOTASK.md](docs/AUTOTASK.md)). None of the three has run against a real account |

### What it is not

- **Not an EDR.** It does not detect intrusions or respond to them: no sensors, no Sigma rules,
  no host isolation, no playbooks, no autonomous response, no AI-agent interface. That code was
  removed in slice 6; the commit it was last built at is kept on the branch
  `archive/action-governance` ([docs/DIRECTION.md](docs/DIRECTION.md)).
- **Not MDM.** No remote wipe, lock or configuration profiles.
- **Not a SIEM.** It does not ingest or search logs.
- **Not a patch deployer.** It reports missing patches; it does not install them.

## Supported platforms

| | Supported |
| --- | --- |
| **Agents: Linux** | Ubuntu 22.04+, Debian 12+, Fedora 43+, RHEL 8+ (and Rocky, AlmaLinux, CentOS Stream), openSUSE Leap 16+ and Tumbleweed — amd64 and arm64 |
| **Agents: Windows** | Windows 11, Windows Server 2022 and 2025 — amd64 (and arm64 binary). **Never run on a real Windows machine**, see [Honest status](#honest-status) |
| **Server** | Any of the Linux distributions above, or the Proxmox LXC installer (Debian) |

macOS is not supported.

The **Supported OS** policy flags hosts on releases their vendor no longer patches. Anything it does
not recognise reads as *unknown*, not failing. As releases reach end of life, raise the minimums
without waiting for a DefendSec release, by setting `DEFENDSEC_SUPPORTED_OS` in
`/etc/defendsec/console.env`, e.g. `fedora=44,rhel=9,windows=26100`.

The server installer handles each distribution's differences:

- It opens ports 47261–47263 in firewalld or ufw when either is active; the uninstaller closes them
  again.
- It allows the control plane's password login in `pg_hba.conf` on Fedora, RHEL and openSUSE.
- On RHEL it selects a supported Postgres module stream (16 or 15), where the default would be the
  end-of-life 10.

## Start here

The quickest path is meant to be a Proxmox LXC: one command, then a browser. That script has not
been run on a Proxmox host yet (see [Honest status](#honest-status)); the server installer on Ubuntu
22.04 and Rocky 9.8 has.

1. **Create the server.** On the Proxmox host, as root. It installs the v0.1.0 release (prebuilt
   and checksummed, nothing is compiled) in a new Debian 12 container, and starts the first
   vulnerability feed sync.

   ```bash
   curl -fL --progress-bar \
     https://github.com/WASP512/defendsec/releases/download/v0.1.0/create-proxmox-ct.sh \
     -o /tmp/defendsec.sh && bash /tmp/defendsec.sh
   ```

   To install on a plain Linux VM running any supported distribution, see
   [docs/INSTALL.md](docs/INSTALL.md).

2. **Claim it.** Open `https://<server-ip>:47261`. The certificate is self-signed at first; see
   INSTALL.md to verify its fingerprint or replace it.

   A new install shows **Finish setting up DefendSec**. Create your account and you are the first
   administrator. That open setup lasts 30 minutes after the server starts. After that, prove you
   own the server by running this on it, then open the one-time link it prints:

   ```bash
   pct exec <CTID> -- defendsec-apid bootstrap-admin    # Proxmox
   sudo defendsec-apid bootstrap-admin                  # any other server
   ```

   The link works once, expires after an hour, and stops working once an account exists.

3. **Enroll hosts.** The **Enroll** page has a ready-to-paste command for each platform:

   | Platform | How |
   | --- | --- |
   | Linux (amd64/arm64): Ubuntu, Debian, Fedora, RHEL and rebuilds, openSUSE | `install-agent.sh`, run with sudo. It uses the host's own package manager and installs a systemd service |
   | Windows | `install-agent.ps1` in an elevated Windows PowerShell, or the **MSI** for Intune / SCCM / GPO |
   | Fleets | The [Ansible role](packaging/ansible) or [Terraform module](packaging/terraform/defendsec-agent) |

   Downloads are checksum-verified and pinned to your server's certificate. Nothing asks you to
   disable TLS verification.

4. **Uninstall.** Every host's page ends with the exact uninstall command for its platform. The
   uninstallers also ship with each release and are served from your server's `/downloads`.

## Key settings

| Setting | Where | What it does |
| --- | --- | --- |
| `DEFENDSEC_SETUP_WINDOW` | `apid.env` | How long open first-run setup lasts (default `30m`); `off` leaves only `bootstrap-admin` or the admin token for creating the first account |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `apid.env` | OpenTelemetry traces of apid's own work |
| `DEFENDSEC_METRICS_ADDR` | `apid.env` | Serve Prometheus metrics beyond loopback (requires `DEFENDSEC_METRICS_TOKEN`) |
| `DEFENDSEC_DB_MAX_CONNS` | `apid.env` | Postgres pool size for large fleets (default 20) |
| `DEFENDSEC_SUPPORTED_OS` | `console.env` | Raise the Supported OS minimums |

Everything else is in [docs/OPERATIONS.md](docs/OPERATIONS.md). That document and
[docs/INSTALL.md](docs/INSTALL.md) were written before the direction change and have been edited to
drop the detection and response settings; where they disagree with this README, this README and
[docs/DIRECTION.md](docs/DIRECTION.md) win.

## Documentation

| If you want… | Read |
| --- | --- |
| Where the product is going, what is being removed, and the plan | [docs/DIRECTION.md](docs/DIRECTION.md) |
| What has actually been run, and what happened | [docs/VERIFIED.md](docs/VERIFIED.md) |
| Install, enroll and uninstall, step by step | [docs/INSTALL.md](docs/INSTALL.md) |
| Operations: backup, HTTPS, SSO, metrics, scale | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Windows specifics, and what is verified there | [docs/WINDOWS.md](docs/WINDOWS.md) |
| The history of the earlier detection-and-response phase (superseded) | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Architecture and security model (written before the direction change; it still describes the detection and response features removed in slice 6) | [Technical white paper (PDF)](docs/DefendSec-Technical-White-Paper.pdf) |
| Fedora developer lab | [docs/FEDORA.md](docs/FEDORA.md) |

### Honest status

- **Findings come from the synced distro feeds.** The matcher compares each package against the
  distro's own fixed versions (Ubuntu, Debian, RHEL family, SUSE), so backported fixes are not
  flagged. Measured on a fully patched Ubuntu 22.04: 0 findings. On a fully patched **Rocky 9.8**
  the answer depends on the hour: while only Red Hat had published a kernel fix, the 8 kernel CVEs
  were `awaiting_vendor` (watch list, not in Fix this week); once Rocky's errata feed published it
  (2026-10-24) the same up-to-date host showed 8 *fixable* findings naming a kernel version Rocky's
  mirrors did not carry yet, so `dnf` had nothing to install. A Rocky/Alma "fix available" row can
  therefore be ahead of your repositories by hours. Debian's tracker lists open CVEs, so a patched
  Debian host still shows `unfixed` rows. Only Ubuntu 22.04 and Rocky 9.8 have been matched on a
  real host; see `docs/VERIFIED.md`.
- **The Windows agent has never been run on a real Windows machine.** It has been verified by
  cross-compilation, parser tests and PowerShell parse checks only. That covers the service,
  inventory and posture checks. Treat any Windows deployment as an experiment. The Windows agent is
  inventory and posture only; its service and MSI stay until the Datto RMM collector covers Windows
  hosts ([docs/WINDOWS.md](docs/WINDOWS.md)).
- **Only two server installs have been run: Ubuntu 22.04 and Rocky 9.8** (SELinux enforcing), from a
  local copy of the release. The Proxmox container script `create-proxmox-ct.sh` (Debian 12) has only
  been syntax-checked, and Debian 12, Fedora, openSUSE and arm64 installs have not been run. The
  download-from-GitHub and verify-a-published-release paths are first exercised by the v0.1.0 tag.
- **The Datto RMM collector, the Microsoft 365 collector and Autotask have not been run against a
  real account or tenant.** They are tested against fakes and fixtures. Surface findings, identity
  findings and tickets are real code paths with synthetic evidence only
  ([docs/VERIFIED.md](docs/VERIFIED.md)).
- **The Postgres-backed tests run in CI** (and against a test database during each slice); the
  baseline host that skipped them is history.
- **The server holds the fleet in memory**, about 1.9 GB at 10,000 hosts, measured in an earlier
  load test of the earlier-phase code ([docs/LOADTEST.md](docs/LOADTEST.md)). The figure has not
  been re-measured against this release.

## Verify what you run

Releases are reproducible builds with CycloneDX SBOMs. `SHA256SUMS` is signed with Sigstore
keyless signing and carries GitHub build provenance (shipped in the release, so it verifies
offline). `scripts/verify-release.sh --strict --reproduce` checks all of it, including a rebuild
from source that must match byte for byte, and `scripts/check-reproducible.sh` rebuilds and
compares in CI. *Verify our binaries with the same rigor we help you apply to your fleet.*
See [docs/OPERATIONS.md](docs/OPERATIONS.md#verifying-a-defendsec-release) and the
[changelog](CHANGELOG.md).

## Developers

```bash
npm install && npm run dev                    # console on http://127.0.0.1:47261
npm test                                      # console unit tests
npm run lint
go build ./... && go vet ./...
go test ./...                                 # set TEST_DATABASE_URL to include the Postgres tests
```

In development, when `DEFENDSEC_ADMIN_TOKEN` is unset, the admin token is
`defendsec-local-admin`. Production installs generate a random one.

CI runs:

- Go build, vet and tests, including the Postgres integration tests
- the reproducible-build check and govulncheck
- `terraform test` and `ansible-lint`
- a PowerShell parse of every Windows script
- the console's lint, tests, build and `npm audit`
- a secret scan (TruffleHog)
- one test of code that is being removed (see [docs/DIRECTION.md](docs/DIRECTION.md))

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). Copyright © 2026 Mason Hargrove /
AllTech.

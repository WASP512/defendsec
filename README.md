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
| **What is exploitable right now?** | Matches installed software against an advisory catalog, with triage and acknowledgement. `defendsec-feeds` syncs CISA KEV, EPSS and the Ubuntu, Debian, Red Hat and SUSE advisories into the database, and the Advisories page shows how old they are ([docs/FEEDS.md](docs/FEEDS.md)) | **The matcher does not use that data yet:** it still matches the hard-coded console catalog. No KEV → EPSS → CVSS ranking and no distro-aware fixed versions in findings. Slices 4–5 of the [plan](docs/DIRECTION.md) |
| **What is end-of-life or unpatched?** | Hardware, OS, software and pending patches per host on Linux (apt, dnf/yum, zypper) and Windows (Windows Update), with package change history. A **Supported OS** policy flags hosts on releases their vendor no longer patches | Pending patches ranked by age |
| **What is misconfigured?** | 42 SCA checks in control-tagged packs. On Linux the CIS-aligned checks know each distro: its package names, SELinux on Fedora, RHEL and openSUSE, AppArmor on Ubuntu and Debian. On Windows: BitLocker, Defender, firewall, SMBv1, UAC and RDP. Firewall state is read from ufw, firewalld or plain nftables. A check the host cannot answer is reported as missing evidence | |
| **What is exposed from the outside?** | An external surface scanner: declared domains, hostnames and IPs (each confirmed as authorised to test) are checked daily and on demand for SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, CAA, dangling CNAMEs, certificate expiry and chain, legacy TLS and exposed ports, on the Assets and Surface pages ([docs/SURFACE.md](docs/SURFACE.md)). A check that could not run is shown as not assessed, never as a pass | Surface findings in the ranked weekly list and the trendline (slice 7b) |
| **Is it getting better?** | Control mapping for NIST 800-53, 800-171, CIS v8, CMMC and CJIS; audit periods, documented exceptions, a hash-chained audit ledger and offline-verifiable evidence exports | The ranked weekly list and the trendline (slice 5) |

Alongside that:

| Area | What you get |
| --- | --- |
| **File integrity** | Hash-based checks on sensitive paths, with baselines you accept explicitly. On Linux: account, SSH, sudo and crypto-policy files. On Windows: `hosts`, `services`, Group Policy scripts and scheduled tasks |
| **Accounts** | Named users, TOTP, lockout, OIDC single sign-on, and an audit ledger of every action |
| **Integrations** | Prometheus metrics, OpenTelemetry traces, an Ansible role and a Terraform module for rollout |

### What it is not

- **Not an EDR.** It does not detect intrusions or respond to them: no sensors, no Sigma rules,
  no host isolation, no playbooks, no autonomous response, no AI-agent interface. That code is
  still in the repository today and is being removed ([docs/DIRECTION.md](docs/DIRECTION.md)); it
  is not maintained, not documented here and not supported.
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

Most people run the server as a Proxmox LXC: one command, then a browser.

1. **Create the server.** On the Proxmox host, as root. The first install often takes 15–30
   minutes while it builds.

   ```bash
   curl -fL --progress-bar \
     https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh \
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
[docs/INSTALL.md](docs/INSTALL.md) were written before the direction change and still describe detection and
response settings that are being removed. Where they disagree with this README, this README and
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
| Architecture and security model (written before the direction change) | [Technical white paper (PDF)](docs/DefendSec-Technical-White-Paper.pdf) |
| Fedora developer lab | [docs/FEDORA.md](docs/FEDORA.md) |

### Honest status

- **Findings come from the synced distro feeds, with one known false-positive class.** The matcher
  compares each package against the distro's own fixed versions (Ubuntu, Debian, RHEL family, SUSE),
  so backported fixes are not flagged. Measured on a fully patched Ubuntu 22.04: 0 findings. On a
  fully patched **Rocky 9** it reports the kernel CVEs Red Hat fixed in a build Rocky has not shipped
  yet, because Rocky and Alma hosts are matched against Red Hat's feed. Until Rocky's own errata feed
  is added, a Rocky/Alma "fix available" row may name a version your repositories do not have yet.
  See `docs/VERIFIED.md`.
- **The Windows agent has never been run on a real Windows machine.** It has been verified by
  cross-compilation, parser tests and PowerShell parse checks only. That covers the service,
  inventory and posture checks. Treat any Windows deployment as an experiment. Windows service and
  MSI packaging is on the removal list in [docs/DIRECTION.md](docs/DIRECTION.md).
- **The Postgres-backed tests were not run in the baseline.** The Go tests that need a database
  (105 of them) skip on the host the baseline ran on. CI is configured to run them; CI results
  were not checked. See [docs/VERIFIED.md](docs/VERIFIED.md).
- **The external surface scanner, the exposure ranking and the trendline do not exist yet.**
- **The server holds the fleet in memory**, about 1.9 GB at 10,000 hosts, measured in an earlier
  load test of the earlier-phase code ([docs/LOADTEST.md](docs/LOADTEST.md)). The load tool is on the
  removal list, and the figure has not been re-measured.

## Verify what you run

Releases are reproducible builds with CycloneDX SBOMs. `SHA256SUMS` is signed with Sigstore
keyless signing and carries GitHub build provenance. `scripts/verify-release.sh` checks all of
it, and `scripts/check-reproducible.sh` rebuilds and compares. *Verify our binaries with the same
rigor we help you apply to your fleet.*

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

# DefendSec

**Endpoint security you run yourself, and can prove works.**

DefendSec is a self-hosted platform for watching and defending the machines you own. It covers
Linux, Windows and macOS. One server, one small agent per host. No vendor cloud, no per-seat
subscription, no telemetry leaving your network.

## Why DefendSec exists

Small security teams, MSPs, schools, local government, labs and regulated shops sit in a gap:

- **Commercial EDR** is built for the enterprise. It is priced per endpoint per year, sends your
  host data to someone else's cloud, and asks you to trust detection logic you cannot inspect.
- **Open-source building blocks** (osquery, Wazuh, auditd, a SIEM) are powerful. But assembling
  them into something you can operate, and defend to an auditor, is a project in its own right.
- **Compliance frameworks** (CIS, NIST 800-53 / 800-171, CMMC, CJIS) ask for *evidence*, not
  dashboards. Most tools show you a green tile and leave you to argue that it means something.

DefendSec fills that gap. It is a complete, self-contained product built around three ideas:

1. **You own it.** Everything runs on your hardware, including the vulnerability catalog,
   detection rules and audit log. It works air-gapped.
2. **Every claim is checkable.** Configuration results carry their control IDs. The audit ledger
   is hash-chained and can be anchored externally. Evidence bundles verify offline with a
   standalone tool. Release binaries are reproducible, signed and ship with SBOMs.
3. **It tells you what it can't see.** Coverage views lead with blind spots, and unknown results
   are reported as missing evidence rather than passes. The docs state plainly what has and
   hasn't been verified.

### Who it's for

- **IT and security teams of one to twenty** who need fleet visibility and response, without an
  enterprise EDR contract.
- **MSPs and consultants** who want one self-hosted stack per client, not a shared SaaS tenant.
- **Regulated and sensitive environments** — government, education, health, defense suppliers
  working toward CMMC — where data residency and audit evidence matter.
- **Homelabs and training environments**, like the Proxmox installer, that want the real thing.

## What it does

| Area | What you get |
| --- | --- |
| **Inventory** | Hardware, OS, software and pending patches on Linux, Windows and macOS, with package change history |
| **Vulnerabilities** | Advisory matching against installed software, with an optional OSV ingest, triage and acknowledgement |
| **Configuration & posture** | SCA packs (CIS-aligned Linux checks; BitLocker, Defender, firewall, SMBv1, UAC and RDP on Windows; FileVault, SIP, Gatekeeper and XProtect on macOS), each tagged to framework controls |
| **File integrity** | Hash-based FIM on sensitive paths, with baselines you accept explicitly |
| **Detection** | Process telemetry (eBPF on Linux, process sampling or opt-in ETW on Windows, sampling on macOS), Sigma rules and a coverage page that leads with blind spots |
| **Response** | Signed commands: host isolation on all three platforms, kill process, live queries, quarantine. Governed by a deny-by-default policy engine with host classes, two-person approval, break-glass and playbooks |
| **Compliance** | Control mapping for NIST 800-53, 800-171, CIS v8, CMMC and CJIS; audit periods, documented exceptions and offline-verifiable evidence exports |
| **Accounts** | Named users, TOTP, lockout, OIDC single sign-on and a hash-chained audit ledger of every action |
| **AI agents, safely** | An MCP interface where AI agents can read and *propose*, but never sign. Humans approve, within blast-radius limits |
| **Integrations** | Syslog, CEF, webhook, Slack, Teams, OpenTelemetry (traces and logs), Prometheus metrics, and an Ansible role and Terraform module for rollout |
| **Scale** | Postgres-primary, with a paged and filtered fleet API. Load-tested at 10,000 hosts with zero errors ([results](docs/LOADTEST.md)) |

### What it is not

- **Not MDM.** No remote wipe, lock, DEP or configuration profiles.
- **Not a SIEM.** It keeps a short event window and forwards everything else to the log platform
  you already run.
- **Not a patch deployer.** It reports missing patches; it does not install them.

## Start here

Most people run the server as a Proxmox LXC: one command, then a browser.

1. **Create the server.** On the Proxmox host, as root. The first install often takes 15–30
   minutes while it builds.

   ```bash
   curl -fL --progress-bar \
     https://raw.githubusercontent.com/WASP512/defendsec/main/packaging/proxmox/ct/defendsec.sh \
     -o /tmp/defendsec.sh && bash /tmp/defendsec.sh
   ```

   On a plain Linux VM, see [docs/INSTALL.md](docs/INSTALL.md).

2. **Claim it.** Open `https://<server-ip>:47261`. The certificate is self-signed at first; see
   INSTALL.md to verify its fingerprint or replace it. A new install shows **Finish setting up
   DefendSec**. Create your account and you are the first administrator. That open setup lasts 30
   minutes after the server starts. After that, prove you own the server by running this on it,
   and open the one-time link it prints:

   ```bash
   pct exec <CTID> -- defendsec-apid bootstrap-admin    # Proxmox
   sudo defendsec-apid bootstrap-admin                  # any other server
   ```

3. **Enroll hosts.** The **Enroll** page has a ready-to-paste command for each platform:

   | Platform | How |
   | --- | --- |
   | Linux (amd64/arm64) | `install-agent.sh`, run with sudo; installs a systemd service |
   | Windows | `install-agent.ps1` in an elevated Windows PowerShell, or the **MSI** for Intune / SCCM / GPO |
   | macOS | `install-agent-macos.sh` with sudo; installs a launchd daemon |
   | Fleets | The [Ansible role](packaging/ansible) or [Terraform module](packaging/terraform/defendsec-agent) |

   Downloads are checksum-verified and pinned to your server's certificate. Nothing asks you to
   disable TLS verification.

4. **Uninstall.** Every host's page ends with the exact uninstall command for its platform. The
   uninstallers also ship with each release and are served from your server's `/downloads`.

## Documentation

| If you want… | Read |
| --- | --- |
| Install, enroll and uninstall, step by step | [docs/INSTALL.md](docs/INSTALL.md) |
| Operations: backup, HTTPS, SSO, policy, forwarding, metrics, scale | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Windows and macOS specifics, and what is verified there | [docs/WINDOWS.md](docs/WINDOWS.md), [docs/MACOS.md](docs/MACOS.md) |
| The 10,000-host load test | [docs/LOADTEST.md](docs/LOADTEST.md) |
| What is built, and what is next | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Architecture and security model | [Technical white paper (PDF)](docs/DefendSec-Technical-White-Paper.pdf) |
| Fedora developer lab | [docs/FEDORA.md](docs/FEDORA.md) |

### Honest status

Linux is the most mature platform.

- **Windows and macOS agents** are feature-complete, but have so far been verified by
  cross-compilation, parser tests and script checks rather than on real machines. Treat your first
  deployment on each as a pilot.
- **Windows ETW** process tracing is opt-in until it has been field-tested.
- **Full process visibility on macOS** (EndpointSecurity) is waiting on an Apple-granted
  entitlement. The Mac agent samples processes until then, and says so.

## Verify what you run

Releases are reproducible builds with CycloneDX SBOMs. `SHA256SUMS` is signed with Sigstore
keyless signing and carries GitHub build provenance. `scripts/verify-release.sh` checks all of
it, and `scripts/check-reproducible.sh` rebuilds and compares. *Verify our binaries with the same
rigor we help you apply to your fleet.*

## Developers

```bash
npm install && npm run dev            # console on http://127.0.0.1:47261
go test ./...                         # set TEST_DATABASE_URL to include the Postgres tests
```

In development, when `DEFENDSEC_ADMIN_TOKEN` is unset, the admin token is
`defendsec-local-admin`. Production installs generate a random one.

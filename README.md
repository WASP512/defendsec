# DefendSec

**Endpoint security you run yourself, and can prove works.**

DefendSec is a self-hosted platform for watching and defending the machines you own. It covers
Linux and Windows: one server, and one small agent per host. There is no vendor cloud, no per-seat
subscription, and no telemetry leaving your network.

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
2. **Every claim is checkable.** Configuration results carry their control IDs, and the audit
   ledger is hash-chained and can be anchored externally. Evidence bundles verify offline with a
   standalone tool. Release binaries are reproducible, signed and ship with SBOMs.
3. **It tells you what it can't see.** Coverage views lead with blind spots. A check the host
   could not answer is reported as missing evidence, never as a pass or a failure. The docs state
   plainly what has and hasn't been verified.

### Who it's for

- **IT and security teams of one to twenty** who need fleet visibility and response, without an
  enterprise EDR contract.
- **MSPs and consultants** who want one self-hosted stack per client, not a shared SaaS tenant.
- **Regulated and sensitive environments** — government, education, health, defense suppliers
  working toward CMMC — where data residency and audit evidence matter.
- **Homelabs and training environments**, via the Proxmox installer, that want the real thing.

## What it does

| Area | What you get |
| --- | --- |
| **Inventory** | Hardware, OS, software and pending patches on Linux (apt, dnf/yum, zypper) and Windows (Windows Update), with package change history |
| **Vulnerabilities** | Advisory matching against installed software, with an optional OSV ingest, triage and acknowledgement |
| **Configuration & posture** | SCA packs, each tagged to framework controls. On Linux the CIS-aligned checks know each distro: its package names, SELinux on Fedora, RHEL and openSUSE, AppArmor on Ubuntu and Debian. On Windows: BitLocker, Defender, firewall, SMBv1, UAC and RDP. Firewall state is read from ufw, firewalld or plain nftables. A check the host cannot answer raises no alert |
| **File integrity** | Hash-based FIM on sensitive paths, with baselines you accept explicitly. On Linux: account, SSH, sudo and crypto-policy files. On Windows: `hosts`, `services`, Group Policy scripts and scheduled tasks |
| **Detection** | Process telemetry (eBPF on Linux; process sampling or opt-in ETW on Windows), Sigma rules, and a coverage page that leads with blind spots |
| **Response** | Signed commands: isolate, kill process, quarantine, and live queries on both platforms (processes, listening ports, users, sessions, scheduled jobs, services, mounts). Governed by a deny-by-default policy engine with host classes, two-person approval, break-glass and playbooks |
| **Host isolation** | Only the control plane stays reachable, so the agent can always receive *release*. Everything else is blocked in both directions. On Linux it uses nftables, covering IPv4 and IPv6; connections already open are cut, it holds alongside firewalld or ufw, and it is re-applied after a reboot. On Windows it uses Windows Firewall, and restores your exact firewall settings on release |
| **Compliance** | Control mapping for NIST 800-53, 800-171, CIS v8, CMMC and CJIS; audit periods, documented exceptions and offline-verifiable evidence exports |
| **Accounts** | Named users, TOTP, lockout, OIDC single sign-on, and a hash-chained audit ledger of every action |
| **AI agents, safely** | An MCP interface where AI agents can read and *propose*, but never sign. Humans approve, within blast-radius limits |
| **Integrations** | Syslog, CEF, webhook, Slack, Teams, OpenTelemetry (traces and logs) and Prometheus metrics, plus an Ansible role and a Terraform module for rollout |
| **Scale** | Postgres-primary, with a paged and filtered fleet API. Load-tested at 10,000 hosts with zero errors ([results](docs/LOADTEST.md)) |

### What it is not

- **Not MDM.** No remote wipe, lock, DEP or configuration profiles.
- **Not a SIEM.** It keeps a short event window and forwards everything else to the log platform
  you already run.
- **Not a patch deployer.** It reports missing patches; it does not install them.

## Supported platforms

| | Supported |
| --- | --- |
| **Agents: Linux** | Ubuntu 22.04+, Debian 12+, Fedora 43+, RHEL 8+ (and Rocky, AlmaLinux, CentOS Stream), openSUSE Leap 16+ and Tumbleweed — amd64 and arm64 |
| **Agents: Windows** | Windows 11, Windows Server 2022 and 2025 — amd64 (and arm64 binary) |
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

4. **Turn on network isolation where you want it.** Until you do, *isolate* only marks a host in
   the console. On each host that should be isolatable:

   ```bash
   # Linux
   echo DEFENDSEC_ISOLATE_NET=1 | sudo tee -a /etc/defendsec/agentd.env && sudo systemctl restart defendsec-agentd
   ```

   ```powershell
   # Windows, elevated
   reg add HKLM\SYSTEM\CurrentControlSet\Services\DefendSecAgent /v Environment /t REG_MULTI_SZ /d DEFENDSEC_ISOLATE_NET=1 /f
   Restart-Service DefendSecAgent
   ```

   The Windows `Environment` value holds all of the service's settings. To set more than one,
   separate them with `\0`, e.g. `/d "DEFENDSEC_ISOLATE_NET=1\0DEFENDSEC_ETW=1"`.

5. **Uninstall.** Every host's page ends with the exact uninstall command for its platform. The
   uninstallers also ship with each release and are served from your server's `/downloads`.

## Key settings

| Setting | Where | What it does |
| --- | --- | --- |
| `DEFENDSEC_ISOLATE_NET=1` | agent | Lets *isolate* cut the host's network (see step 4) |
| `DEFENDSEC_ETW=1` | agent (Windows) | Uses ETW to see every process start, instead of sampling |
| `DEFENDSEC_SETUP_WINDOW` | `apid.env` | How long open first-run setup lasts (default `30m`); `off` leaves only `bootstrap-admin` or the admin token for creating the first account |
| `DEFENDSEC_FORWARD` | `apid.env` | Forward events and alerts: `syslog=`, `cef=`, `webhook=`, `slack=`, `teams=`, `otlp=`, `file=` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `apid.env` | OpenTelemetry traces of apid's own work |
| `DEFENDSEC_METRICS_ADDR` | `apid.env` | Serve Prometheus metrics beyond loopback (requires `DEFENDSEC_METRICS_TOKEN`) |
| `DEFENDSEC_DB_MAX_CONNS` | `apid.env` | Postgres pool size for large fleets (default 20) |
| `DEFENDSEC_SUPPORTED_OS` | `console.env` | Raise the Supported OS minimums |

Everything else is in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documentation

| If you want… | Read |
| --- | --- |
| Install, enroll and uninstall, step by step | [docs/INSTALL.md](docs/INSTALL.md) |
| Operations: backup, HTTPS, SSO, isolation, policy, forwarding, metrics, scale | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Windows specifics, and what is verified there | [docs/WINDOWS.md](docs/WINDOWS.md) |
| The 10,000-host load test | [docs/LOADTEST.md](docs/LOADTEST.md) |
| What is built, and what is next | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Architecture and security model | [Technical white paper (PDF)](docs/DefendSec-Technical-White-Paper.pdf) |
| Fedora developer lab | [docs/FEDORA.md](docs/FEDORA.md) |

### Honest status

Linux is the most mature platform.

- **Linux isolation** is tested in CI against real traffic in network namespaces, for both the
  nftables and iptables backends. The tests check that the control plane stays reachable,
  everything else is blocked in both directions and both address families, an open session is
  cut, isolation is restored after a reboot, and nothing is left behind on release.
- **The Windows agent** is feature-complete, but it has so far been verified by cross-compilation,
  parser tests and PowerShell parse checks, not on real machines. That covers the service,
  isolation, live queries and posture. Treat your first Windows deployment as a pilot.
- **Windows ETW** process tracing is opt-in until it has been field-tested.
- **Slack and Teams** alerting is tested for payload shape only, not against real workspaces.
- **The server holds the fleet in memory**, about 1.9 GB at 10,000 hosts. That is the next
  scaling limit.

## Verify what you run

Releases are reproducible builds with CycloneDX SBOMs. `SHA256SUMS` is signed with Sigstore
keyless signing and carries GitHub build provenance. `scripts/verify-release.sh` checks all of
it, and `scripts/check-reproducible.sh` rebuilds and compares. *Verify our binaries with the same
rigor we help you apply to your fleet.*

## Developers

```bash
npm install && npm run dev                    # console on http://127.0.0.1:47261
npm test                                      # console unit tests
go test ./...                                 # set TEST_DATABASE_URL to include the Postgres tests
sudo ./scripts/test-isolation-netns.sh        # Linux isolation against real traffic (root, nft, iptables)
go run ./cmd/defendsec-loadtest -agents 1000 -enroll-secret S -admin-token T  # load-test a running apid
```

In development, when `DEFENDSEC_ADMIN_TOKEN` is unset, the admin token is
`defendsec-local-admin`. Production installs generate a random one.

CI runs:

- Go vet and tests, including the Postgres integration tests
- the reproducible-build check and govulncheck
- the isolation namespace test
- `terraform test` and `ansible-lint`
- a PowerShell parse of every Windows script
- the console's lint, tests and build

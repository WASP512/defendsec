# DefendSec on Windows (roadmap 5.1)

## What the agent does on Windows

| Area | How | Notes |
| --- | --- | --- |
| Service | `DefendSecAgent`, LocalSystem, automatic start, restart on failure | Installed by `install-agent.ps1` or the MSI. Logs to `C:\ProgramData\DefendSec\agent\agent.log`; start, stop and fatal errors also go to the Application event log. |
| Posture | One PowerShell script per inventory report | BitLocker (protection **on**, not merely encrypted), Defender antivirus / real-time / tamper protection / definition age (≤ 3 days), firewall on for every profile, SMBv1 off, UAC on, RDP off or requiring NLA. Evaluated as the `windows-posture` SCA pack, control-tagged. |
| Inventory | Same script, plus the Windows Update Agent | OS, build, memory, uptime, serial, model, installed programs (both registry hives), pending updates. |
| Process events | Process-table sampling by default; ETW opt-in | See below. |
| `kill_process` | Toolhelp + TerminateProcess | Names match case-insensitively with or without `.exe`. Core system processes (`lsass`, `csrss`, `wininit`, `winlogon`, `services`, `smss`, `svchost`, `MsMpEng`) are refused. |
| Isolation | Windows Firewall (`netsh advfirewall`) | Needs `DEFENDSEC_ISOLATE_NET=1`, as on Linux. Before changing anything it records each profile's state and policy. It then allows outbound TCP only to the control plane and blocks inbound, overriding allow rules such as RDP, and sets block-outbound. Release deletes its rules and restores the recorded profiles. A domain GPO that manages the firewall can override this. |
| File integrity | The same hash-based FIM as Linux | Watches `hosts` and `services`, Group Policy machine scripts and `System32\Tasks` (scheduled tasks) by default; add paths with `DEFENDSEC_FIM_PATHS`. |
| Live queries | PowerShell and the process table | `processes` (with command lines), `listening_ports` (TCP listeners and UDP endpoints, with owning process), `users` (local accounts), `logged_in_users` (`quser`), `crontab` = scheduled tasks with their actions, `systemd_units` = services with their binary paths, `mounts` = volumes, `os_info`. Output is cast to plain types in the script and parsed by tested code; the scripts are checked to parse under PowerShell in CI. |

A posture probe that cannot run — a cmdlet missing on Home edition, Defender
absent because another antivirus is installed — is reported as *unknown* and
produces no SCA result. The compliance view shows missing evidence as missing,
rather than as a pass or a failure.

## Process visibility

The default sensor samples the process table every few seconds. It records the
full image path, parent, and command line (read with
`ProcessCommandLineInformation`, which does not read the target's memory), but
a process that starts and exits between samples is never seen.

Setting `DEFENDSEC_ETW=1` in the service's environment switches to an Event
Tracing for Windows consumer (`Microsoft-Windows-Kernel-Process`, process
start). It sees every execution. It is opt-in because it has not yet been
exercised on Windows hosts by DefendSec's own tests: the Win32 structure layouts
are checked against the SDK sizes and the event parser against manifest-shaped
records, both on Linux, but the live session has only been compiled. If the
session fails to start — it needs administrator or SYSTEM, and Windows allows 64
sessions — the agent logs why and falls back to sampling, and the coverage page
reports the sensor actually running.

To enable it:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Services\DefendSecAgent /v Environment /t REG_MULTI_SZ /d DEFENDSEC_ETW=1 /f
Restart-Service DefendSecAgent
```

## The MSI

`defendsec-agent-windows-amd64.msi` is built on Linux with `wixl` by
`scripts/build-msi.sh`. It installs the agent and `uninstall-agent.ps1` to
`C:\Program Files\DefendSec` and registers the service. It is not
byte-reproducible (Windows Installer requires a new package code for every
build); the agent binary inside it is. To check it:

```bash
msiextract defendsec-agent-windows-amd64.msi
sha256sum DefendSec/defendsec-agentd.exe   # matches defendsec-agentd-windows-amd64.exe in SHA256SUMS
```

The MSI is not Authenticode-signed. The release's `SHA256SUMS` is signed with
Sigstore (see OPERATIONS.md); code-signing the MSI and the executable needs a
certificate the project does not yet hold.

## What has been verified, and where

- Parsers for every posture and inventory source, against captured output.
- `WindowsScript` itself, run under PowerShell 7 on Linux: it parses, isolates
  each failing section, and emits JSON the parser accepts with every probe
  unknown (`internal/posture/testdata`).
- The installer and uninstaller scripts parse under PowerShell 7.
- The MSI builds, and its tables (service install and control, hidden secret
  property) are inspected with `msiinfo`.
- Everything cross-compiles and `go vet`s for `GOOS=windows`.

Not yet verified on a Windows machine: the service lifecycle, the live ETW
session, the installer end to end, and the posture script's values on real
editions. Treat the first Windows deployment as a pilot.

# DefendSec on Windows (roadmap 5.1)

The Windows agent is an **inventory and posture** agent. Slice 6 removed what made the earlier agent
an EDR on Windows: the process sampler, the ETW sensor, isolation through Windows Firewall and
`kill_process`. The service, the posture pack, inventory, file integrity and the MSI stay, because
until the Datto RMM collector covers Windows hosts the agent is the only coverage they have.

## What the agent does on Windows

| Area | How | Notes |
| --- | --- | --- |
| Service | `DefendSecAgent`, LocalSystem, automatic start, restart on failure | Installed by `install-agent.ps1` or the MSI. Logs to `C:\ProgramData\DefendSec\agent\agent.log`; start, stop and fatal errors also go to the Application event log. |
| Posture | One PowerShell script per inventory report | BitLocker (protection **on**, not merely encrypted), Defender antivirus / real-time / tamper protection / definition age (≤ 3 days), firewall on for every profile, SMBv1 off, UAC on, RDP off or requiring NLA. Evaluated as the `windows-posture` SCA pack, control-tagged. |
| Inventory | Same script, plus the Windows Update Agent | OS, build, memory, uptime, serial, model, installed programs (both registry hives), pending updates. |
| File integrity | The same hash-based FIM as Linux | Watches `hosts` and `services`, Group Policy machine scripts and `System32\Tasks` (scheduled tasks) by default; add paths with `DEFENDSEC_FIM_PATHS`. |
| Live queries | PowerShell | Off unless the operator enables `live_query` (OPERATIONS.md). `listening_ports` (TCP listeners and UDP endpoints, with owning process), `users` (local accounts), `logged_in_users` (`quser`), `crontab` = scheduled tasks with their actions, `systemd_units` = services with their binary paths, `mounts` = volumes, `os_info`. Output is cast to plain types in the script and parsed by tested code; the scripts are checked to parse under PowerShell in CI. |

A posture probe that cannot run — a cmdlet missing on Home edition, Defender
absent because another antivirus is installed — is reported as *unknown* and
produces no SCA result. The compliance view shows missing evidence as missing,
rather than as a pass or a failure.

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

Not yet verified on a Windows machine: the service lifecycle, the installer end
to end, and the posture script's values on real editions. No Windows agent code
has ever been run on a real Windows machine. Treat the first Windows deployment as a pilot.

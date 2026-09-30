# DefendSec on macOS (roadmap 5.2)

## What the agent does on macOS

| Area | How | Notes |
| --- | --- | --- |
| Service | launchd daemon `com.defendsec.agentd`, running as root | Installed by `install-agent-macos.sh`. Log: `/Library/Logs/DefendSec/agentd.log`. |
| Posture | `fdesetup`, `socketfilterfw`, `csrutil`, `spctl`, `defaults` | FileVault on (encryption in progress does not pass), application firewall on, stealth mode, SIP fully on (a custom configuration fails), Gatekeeper on, XProtect present, security-data updates installing automatically, automatic login off. Evaluated as the `macos-posture` SCA pack. |
| Inventory | `sw_vers`, `sysctl`, `system_profiler`, `softwareupdate -l` | OS, memory, uptime, model, applications, pending updates. |
| Process events | Process-table sampling (`kern.proc.all`) | Command lines from `kern.procargs2`. The kernel gives only the first 16 characters of an executable's name, not its path. |
| `kill_process` | `kern.proc.all` + SIGTERM | `launchd`, `kernel_task`, `WindowServer` and `loginwindow` are refused. |
| Isolation | pf anchor `com.apple/250.DefendSecIsolate` | Needs `DEFENDSEC_ISOLATE_NET=1`. Allows loopback and the control plane and drops everything else; the agent's existing connection survives. Release flushes the anchor and returns pf's enable reference. |

## Full process visibility: EndpointSecurity

Seeing every execution on macOS, with full paths and arguments, requires Apple's
EndpointSecurity framework. A process can only use it if it is signed with the
`com.apple.developer.endpoint-security.client` entitlement, which Apple grants
per developer team on request. DefendSec does not hold it, so the agent
samples the process table and says so on the Detection coverage page.

What it takes, in order:

1. **Request the entitlement** (the project owner, with an Apple Developer
   Program membership): <https://developer.apple.com/contact/request/system-extension/>,
   choosing *Endpoint Security*. Apple reviews these individually.
2. **Sign and notarize** the agent with a Developer ID certificate and a
   provisioning profile that carries the entitlement. This also removes the
   need to clear quarantine on the binary.
3. **Grant Full Disk Access** to the agent, by MDM profile
   (`com.apple.TCC.configuration-profile-policy`, `SystemPolicyAllFiles`) —
   EndpointSecurity clients refuse to start without it.
4. **Build the ES sensor.** It needs cgo against `libEndpointSecurity`, which
   the current pure-Go release build does not use; it would be built on a
   macOS runner. The sensor interface (`internal/sensor.Sensor`) and the
   fallback wrapper the Windows ETW sensor uses are already in place for it.

Until then the coverage page lists the sampler's limitations, and Sigma rules
that depend on catching short-lived processes should be read with that in mind.

## A .pkg for MDM

`scripts/build-macos-pkg.sh` builds a signed-or-unsigned `.pkg` on a Mac
(it needs `pkgbuild`, which exists only on macOS). The package installs the
agent binary and uninstaller; its postinstall enrolls the host if
`/Library/Application Support/DefendSec/agent.conf` exists — deploy that file
first with your MDM:

```
SERVER_HTTP=https://SERVER:47262
SERVER_GRPC=SERVER:47263
TLS_SERVER_NAME=SERVER
ENROLL_SECRET=SECRET
```

The release does not yet include a `.pkg`, because it is built on Linux.

## What has been verified, and where

Parsers against captured output of every tool above; the `kern.procargs2`
decoder; the scripts' shell syntax; cross-compilation and `go vet` for
`GOOS=darwin`. Not yet run on a Mac by DefendSec's tests. Treat the first
macOS deployment as a pilot.

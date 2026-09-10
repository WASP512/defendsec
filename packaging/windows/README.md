# Windows service

Linux agents are the supported production path ([docs/INSTALL.md](../../docs/INSTALL.md)). On Windows, the agent is still a single binary you run as a service with [WinSW](https://github.com/winsw/winsw) or `sc.exe` after installing `defendsec-agentd.exe`.

Example `defendsec-agentd.xml` next to WinSW:

```xml
<service>
  <id>defendsec-agentd</id>
  <name>DefendSec Agent</name>
  <description>DefendSec mTLS endpoint agent</description>
  <executable>%BASE%\defendsec-agentd.exe</executable>
  <arguments>--server-http https://CONTROL_PLANE:47262 --server-grpc CONTROL_PLANE:47263 --enroll-secret-file C:\ProgramData\defendsec\enroll-secret --state-dir C:\ProgramData\defendsec\agent</arguments>
  <log mode="roll"></log>
</service>
```

Phase 1 does not bundle a native Windows SCM implementation. The process is `Type=simple`: it stays in the foreground until the service manager stops it.

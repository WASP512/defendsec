# Windows service (Phase 1)

The agent is a single binary. Run it as a service with [WinSW](https://github.com/winsw/winsw) or `sc.exe` after installing `keel-agentd.exe`.

Example `keel-agentd.xml` next to WinSW:

```xml
<service>
  <id>keel-agentd</id>
  <name>Keel Agent</name>
  <description>Keel mTLS endpoint agent</description>
  <executable>%BASE%\keel-agentd.exe</executable>
  <arguments>--server-http https://CONTROL_PLANE:47262 --server-grpc CONTROL_PLANE:47263 --enroll-secret-file C:\ProgramData\keel\enroll-secret --state-dir C:\ProgramData\keel\agent</arguments>
  <log mode="roll"></log>
</service>
```

Phase 1 does not bundle a native Windows SCM implementation. The process is `Type=simple`: it stays in the foreground until the service manager stops it.

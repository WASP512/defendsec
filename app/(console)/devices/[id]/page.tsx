import Link from "next/link";
import { notFound } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PolicyBadge, OnlineBadge, SeverityBadge } from "@/components/status-badge";
import { FindingActions } from "@/components/finding-actions";
import { ensureStore } from "@/lib/store";
import { loadMtlsDevices, mergeDevices } from "@/lib/mtls-agents";
import { evaluateDevice, fimDriftPaths, isOnline } from "@/lib/policies";
import { findingsForDevice } from "@/lib/advisories";
import {
  formatBytesMb,
  formatUptime,
  platformLabel,
  relativeTime,
} from "@/lib/format";
import { AcceptBaseline } from "@/components/accept-baseline";

export const dynamic = "force-dynamic";

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const store = await ensureStore();
  const device = mergeDevices(store.devices, await loadMtlsDevices()).find((d) => d.id === id);
  if (!device) notFound();
  const policies = evaluateDevice(device, store.fimEvents, store.triages);
  const findings = findingsForDevice(device, store.triages);
  const drifts = fimDriftPaths(device);
  const events = store.fimEvents.filter((event) => event.deviceId === device.id);

  const facts = [
    ["Platform", `${platformLabel(device.platform)} ${device.osVersion}`.trim()],
    ["Hardware", device.hardwareModel || "—"],
    ["Serial", device.serial || "—"],
    ["CPU", device.cpu || "—"],
    ["Memory", formatBytesMb(device.memoryMb)],
    ["User", device.username || "—"],
    ["Addresses", device.ipAddresses.join(", ") || "—"],
    ["Uptime", formatUptime(device.uptimeSeconds)],
    ["Enrolled", relativeTime(device.enrolledAt)],
    ["Last seen", relativeTime(device.lastSeen)],
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div>
        <Link href="/devices" className="text-sm text-muted-foreground hover:underline">
          ← Hosts
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-3xl font-semibold tracking-tight">{device.hostname}</h1>
          <OnlineBadge online={isOnline(device)} />
          {device.sample ? <Badge variant="outline">sample</Badge> : null}
          {device.hardwareModel === "mTLS gRPC agent" ? (
            <Badge variant="outline">mTLS</Badge>
          ) : null}
        </div>
        <p className="mt-1 text-muted-foreground">
          {device.osName} {device.osVersion} · {device.arch || "unknown arch"}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {facts.map(([label, value]) => (
          <Card key={label}>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {label}
              </CardTitle>
            </CardHeader>
            <CardContent className="font-medium break-all">{value}</CardContent>
          </Card>
        ))}
      </div>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Policies</h2>
        <div className="grid gap-3">
          {policies.map((policy) => (
            <div key={policy.id} className="flex flex-col gap-2 rounded-xl border p-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="font-medium">{policy.name}</p>
                <p className="text-sm text-muted-foreground">{policy.detail}</p>
              </div>
              <PolicyBadge status={policy.status} />
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Advisories</h2>
        {findings.length === 0 ? (
          <p className="text-sm text-muted-foreground">No catalog matches for reported software.</p>
        ) : (
          <ul className="divide-y rounded-xl border">
            {findings.map((finding) => (
              <li key={finding.key} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{finding.advisory.cve}</span>
                    <SeverityBadge severity={finding.advisory.severity} />
                    {finding.status === "acknowledged" ? (
                      <Badge variant="outline">acknowledged</Badge>
                    ) : (
                      <Badge>open</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {finding.packageName} {finding.version} is below {finding.advisory.below}.{" "}
                    {finding.advisory.summary}
                  </p>
                </div>
                <FindingActions findingKey={finding.key} status={finding.status} />
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Pending patches</h2>
        {device.patchInventory !== "ok" ? (
          <p className="text-sm text-muted-foreground">
            {device.patchInventory === "unsupported"
              ? "This platform does not report a patch catalog yet."
              : device.patchInventory === "error"
                ? "The agent could not collect pending updates."
                : "No patch inventory reported yet."}
          </p>
        ) : device.pendingUpdates.length === 0 ? (
          <p className="text-sm text-muted-foreground">No pending updates reported.</p>
        ) : (
          <ul className="divide-y rounded-xl border">
            {device.pendingUpdates.map((item) => (
              <li key={`${item.name}-${item.available}`} className="flex flex-col gap-1 px-4 py-3 text-sm sm:flex-row sm:justify-between">
                <span>{item.name}</span>
                <span className="text-muted-foreground">
                  {item.current} → {item.available}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-lg font-semibold">File integrity</h2>
          {drifts.length > 0 ? <AcceptBaseline deviceId={device.id} /> : null}
        </div>
        {device.fim.length === 0 && device.fimBaseline.length === 0 ? (
          <p className="text-sm text-muted-foreground">No watched paths reported.</p>
        ) : (
          <div className="space-y-3">
            {drifts.length > 0 ? (
              <p className="text-sm text-destructive">
                Drift vs accepted baseline: {drifts.join(", ")}
              </p>
            ) : (
              <p className="text-sm text-muted-foreground">Current hashes match the accepted baseline.</p>
            )}
            <ul className="divide-y rounded-xl border">
              {device.fim.map((file) => {
                const baseline = device.fimBaseline.find((item) => item.path === file.path);
                const changed = Boolean(baseline && baseline.sha256 !== file.sha256);
                return (
                  <li key={file.path} className="px-4 py-3 text-sm">
                    <p className="font-medium">
                      {file.path}
                      {changed ? " · drifted" : ""}
                    </p>
                    <p className="break-all text-muted-foreground">{file.sha256}</p>
                  </li>
                );
              })}
            </ul>
            {events.length > 0 ? (
              <div>
                <h3 className="mb-2 text-sm font-medium">Audit log</h3>
                <ul className="divide-y rounded-xl border">
                  {events.map((event) => (
                    <li key={event.id} className="px-4 py-3 text-sm">
                      <p className="font-medium">{event.path}</p>
                      <p className="break-all text-muted-foreground">
                        {event.previous.slice(0, 12)}… → {event.current.slice(0, 12)}… ·{" "}
                        {relativeTime(event.detectedAt)}
                      </p>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Software versions</h2>
        {device.software.length === 0 ? (
          <p className="text-sm text-muted-foreground">No software inventory reported.</p>
        ) : (
          <ul className="divide-y rounded-xl border">
            {device.software.map((item) => (
              <li key={`${item.name}-${item.version}`} className="flex justify-between px-4 py-3 text-sm">
                <span>{item.name}</span>
                <span className="text-muted-foreground">{item.version}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

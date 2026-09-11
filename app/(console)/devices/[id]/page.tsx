import Link from "next/link";
import { notFound } from "next/navigation";
import { databaseURL } from "@/lib/pg";
import { listAlerts } from "@/lib/alerts";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/console-ui";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { PolicyBadge, OnlineBadge, SeverityBadge } from "@/components/status-badge";
import { FindingActions } from "@/components/finding-actions";
import { ensureStore } from "@/lib/store";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { evaluateDevice, fimDriftPaths, isOnline } from "@/lib/policies";
import { findingsForDevice } from "@/lib/advisories";
import {
  formatBytesMb,
  formatUptime,
  platformLabel,
  relativeTime,
} from "@/lib/format";
import { AcceptBaseline } from "@/components/accept-baseline";
import { ResponsePanel } from "@/components/response-panel";
import { loadCommands } from "@/lib/commands";
import { isReadOnlySession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const store = await ensureStore();
  const device = (await loadFleet(store.devices)).find((d) => d.id === id || d.mtlsDeviceId === id);
  if (!device) notFound();
  const mtlsId = device.mtlsDeviceId || "";
  const fimEvents = [...(await loadMtlsFimEvents()), ...store.fimEvents];
  const policies = evaluateDevice(device, fimEvents, store.triages);
  const findings = findingsForDevice(device, store.triages);
  const drifts = fimDriftPaths(device);
  const events = fimEvents.filter(
    (event) => event.deviceId === device.id || (mtlsId && event.deviceId === mtlsId),
  );
  const commandLog = mtlsId ? await loadCommands(mtlsId) : [];
  const readOnly = await isReadOnlySession();
  const alertDeviceId = mtlsId || device.id;
  let openAlertCount = 0;
  if (databaseURL()) {
    try {
      const alerts = await listAlerts({ deviceId: alertDeviceId, status: "open", limit: 50 });
      openAlertCount = alerts.length;
    } catch {
      openAlertCount = 0;
    }
  }

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
      <PageHeader
        title={device.hostname}
        eyebrow={
          <div className="flex items-center gap-2">
            <Link href="/devices" className="hover:text-foreground hover:underline">Hosts</Link>
            <span aria-hidden="true">/</span>
            <span className="text-foreground">{device.hostname}</span>
          </div>
        }
        description={`${device.osName} ${device.osVersion} · ${device.arch || "unknown arch"}`}
        actions={
          <>
          <OnlineBadge online={isOnline(device)} />
          {device.sample ? <Badge variant="outline">sample</Badge> : null}
          {device.hardwareModel === "mTLS gRPC agent" || device.mtlsDeviceId ? (
            <Badge variant="outline">mTLS</Badge>
          ) : null}
          {device.isolated ? <Badge variant="destructive">isolated</Badge> : null}
          </>
        }
      />
      <div>
        {openAlertCount > 0 ? (
          <p className="text-sm">
            <Link
              href={`/alerts?deviceId=${encodeURIComponent(alertDeviceId)}&status=open`}
              className="font-medium text-destructive underline"
            >
              {openAlertCount} open alert{openAlertCount === 1 ? "" : "s"}
            </Link>
          </p>
        ) : (
          <p className="text-sm">
            <Link href={`/alerts?deviceId=${encodeURIComponent(alertDeviceId)}`} className="text-muted-foreground underline">
              View alerts
            </Link>
          </p>
        )}
      </div>

      <div className="overflow-hidden rounded-xl border bg-card">
        <div className="border-b px-4 py-3">
          <h2 className="font-medium">Host facts</h2>
          <p className="text-sm text-muted-foreground">Latest inventory reported by the agent.</p>
        </div>
        <Table>
          <TableBody>
            {facts.map(([label, value]) => (
              <TableRow key={label}>
                <TableCell className="w-40 text-muted-foreground">{label}</TableCell>
                <TableCell className="break-all font-medium">{value}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Signed response</h2>
        <ResponsePanel
          mtlsDeviceId={mtlsId}
          isolated={Boolean(device.isolated)}
          commands={commandLog}
          readOnly={readOnly}
        />
      </section>

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
                {!readOnly ? (
                  <FindingActions findingKey={finding.key} status={finding.status} />
                ) : null}
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
          {drifts.length > 0 ? <AcceptBaseline deviceId={mtlsId || device.id} /> : null}
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

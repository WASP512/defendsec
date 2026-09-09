import Link from "next/link";
import { notFound } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PolicyBadge, OnlineBadge } from "@/components/status-badge";
import { ensureStore } from "@/lib/store";
import { evaluateDevice } from "@/lib/policies";
import {
  formatBytesMb,
  formatUptime,
  onlineFromLastSeen,
  platformLabel,
  relativeTime,
} from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const store = await ensureStore();
  const device = store.devices.find((d) => d.id === id);
  if (!device) notFound();
  const policies = evaluateDevice(device);

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
          <OnlineBadge online={onlineFromLastSeen(device.lastSeen)} />
          {device.sample ? <Badge variant="outline">sample</Badge> : null}
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
        <h2 className="text-lg font-semibold">Software</h2>
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

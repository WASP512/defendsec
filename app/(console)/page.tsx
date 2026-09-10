import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DeviceTable } from "@/components/device-table";
import { SampleToggle } from "@/components/sample-toggle";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadMtlsDevices, mergeDevices } from "@/lib/mtls-agents";
import { isOnline, policySummary } from "@/lib/policies";
import { allFindings } from "@/lib/advisories";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const store = await ensureStore();
  const fleet = mergeDevices(store.devices, await loadMtlsDevices());
  const devices = fleet.map(publicDevice);
  const online = fleet.filter((d) => isOnline(d)).length;
  const failing = policySummary(store.devices, store.fimEvents, store.triages).reduce(
    (n, p) => n + p.failing,
    0,
  );
  const samples = store.devices.some((d) => d.sample);
  const findings = allFindings(store.devices, store.triages);
  const serious = findings.filter(
    (f) =>
      f.status === "open" &&
      (f.advisory.severity === "critical" || f.advisory.severity === "high"),
  ).length;
  const patches = store.devices.reduce((n, d) => n + d.pendingUpdates.length, 0);

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Fleet</h1>
          <p className="mt-1 max-w-2xl text-muted-foreground">
            Security inventory for machines you enroll: versions, pending patches, a local
            advisory catalog, and file integrity on watched paths. No MDM lock/wipe, no
            subscriptions.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <SampleToggle hasSamples={samples} />
          <Link
            href="/enroll"
            className="inline-flex h-8 items-center rounded-lg bg-primary px-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/80"
          >
            Enroll a host
          </Link>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">Hosts online</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">
            {online}
            <span className="ml-2 text-base font-normal text-muted-foreground">
              / {fleet.length}
            </span>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">
              High+ advisories
            </CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{serious}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Pending patches
            </CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{patches}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Integrity events
            </CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{store.fimEvents.length}</CardContent>
        </Card>
      </div>
      <p className="text-sm text-muted-foreground">
        {failing} policy check{failing === 1 ? "" : "s"} failing across the fleet.
      </p>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Hosts</h2>
          <Link href="/devices" className="text-sm text-muted-foreground underline">
            View all
          </Link>
        </div>
        <DeviceTable devices={devices} />
      </section>
    </div>
  );
}

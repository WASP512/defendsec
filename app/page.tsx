import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DeviceTable } from "@/components/device-table";
import { SampleToggle } from "@/components/sample-toggle";
import { ensureStore, publicDevice } from "@/lib/store";
import { isOnline, policySummary } from "@/lib/policies";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const store = await ensureStore();
  const devices = store.devices.map(publicDevice);
  const online = store.devices.filter((d) => isOnline(d)).length;
  const failing = policySummary(store.devices).reduce((n, p) => n + p.failing, 0);
  const samples = store.devices.some((d) => d.sample);

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Fleet</h1>
          <p className="mt-1 max-w-2xl text-muted-foreground">
            Inventory and policy checks for machines you enroll. This is the open slice: heartbeat,
            hardware, and a few host controls — not Apple/Windows MDM.
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

      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">Hosts</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{store.devices.length}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">Online</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{online}</CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Policy failures
            </CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold">{failing}</CardContent>
        </Card>
      </div>

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

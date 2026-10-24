import { DeviceTable } from "@/components/device-table";
import { DeviceList } from "@/components/device-list";
import { parseDeviceListQuery } from "@/lib/device-list";
import { loadDevicePage } from "@/lib/devices-server";
import { SampleToggle } from "@/components/sample-toggle";
import { PageHeader, StatCard } from "@/components/console-ui";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { isOnline } from "@/lib/policies";
import { fleetAggregates } from "@/lib/fleet-aggregates";
import { getFindingsSummary } from "@/lib/findings";
import { isReadOnlySession } from "@/lib/auth";
import { FileWarning, MonitorCheck, Package, ShieldAlert } from "lucide-react";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const store = await ensureStore();
  const readOnly = await isReadOnlySession();
  const fleet = await loadFleet(store.devices);
  const fimEvents = [...(await loadMtlsFimEvents()), ...store.fimEvents];
  // The host table is the control plane's first page, not the whole fleet:
  // shipping every host to the browser was 42 MB at 10,000 hosts.
  const firstPage = await loadDevicePage(parseDeviceListQuery({}));
  const online = fleet.filter((d) => isOnline(d)).length;
  const aggregates = fleetAggregates(fleet, store.triages, await getFindingsSummary());
  const failing = aggregates.policies.reduce(
    (n, p) => n + p.failing,
    0,
  );
  const samples = store.devices.some((d) => d.sample);
  // null when the control plane could not be asked: shown as unknown, not zero.
  const serious = aggregates.serious;
  const patches = fleet.reduce((n, d) => n + d.pendingUpdates.length, 0);

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <PageHeader
        title="Fleet"
        description={
          <>
            Exposure for the machines you enroll: what is exploitable now (installed
            packages against the security advisories your distribution publishes), what is unpatched,
            and what changed. No MDM lock/wipe, no subscriptions.
          </>
        }
        actions={!readOnly ? (
          <div className="flex flex-wrap gap-2">
            <SampleToggle hasSamples={samples} />
            <Link
              href="/enroll"
              className="inline-flex h-8 items-center rounded-lg bg-primary px-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/80"
            >
              Enroll a host
            </Link>
          </div>
        ) : null}
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Hosts online"
          value={online}
          subtitle={`${fleet.length} enrolled`}
          icon={MonitorCheck}
          tone={online === fleet.length && fleet.length > 0 ? "good" : "neutral"}
        />
        <StatCard
          title="Fix these"
          value={serious ?? "?"}
          subtitle={
            serious === null
              ? "Findings unavailable from the control plane"
              : "Open critical, high or KEV findings with a fix"
          }
          icon={ShieldAlert}
          tone={serious === null ? "neutral" : serious > 0 ? "critical" : "good"}
        />
        <StatCard
          title="Pending patches"
          value={patches}
          subtitle="Updates reported across the fleet"
          icon={Package}
          tone={patches > 0 ? "warning" : "good"}
        />
        <StatCard
          title="Integrity events"
          value={fimEvents.length}
          subtitle={`${failing} policy check${failing === 1 ? "" : "s"} failing`}
          icon={FileWarning}
          tone={fimEvents.length > 0 ? "critical" : "good"}
        />
      </div>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Hosts</h2>
          <Link href="/devices" className="text-sm text-muted-foreground underline">
            View all
          </Link>
        </div>
        {"page" in firstPage ? (
          <DeviceList query={parseDeviceListQuery({})} page={firstPage.page} />
        ) : (
          <DeviceTable devices={fleet.slice(0, 200).map(publicDevice)} />
        )}
      </section>
    </div>
  );
}

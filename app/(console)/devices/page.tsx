import { DeviceTable } from "@/components/device-table";
import { DeviceList } from "@/components/device-list";
import { PageHeader } from "@/components/console-ui";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";
import { parseDeviceListQuery } from "@/lib/device-list";
import { loadDevicePage } from "@/lib/devices-server";

export const dynamic = "force-dynamic";

export default async function DevicesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const query = parseDeviceListQuery(await searchParams);
  const result = await loadDevicePage(query);
  const store = await ensureStore();
  // Hosts that check in over the legacy HTTP path (the Python agent, the
  // sample fleet) live only in the console's own file, not in the control
  // plane, and are few by nature; they are listed separately.
  const legacy = store.devices.filter((d) => !d.mtlsDeviceId).map(publicDevice);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Hosts"
        description="Enrolled agents, filtered and paged by the control plane."
      />
      {"page" in result ? (
        <DeviceList query={query} page={result.page} />
      ) : (
        <>
          <p className="rounded-xl border border-destructive/40 p-4 text-sm">
            {result.error} Showing the console&apos;s local copy instead, which is not paged.
          </p>
          <DeviceTable devices={(await loadFleet(store.devices)).map(publicDevice)} />
        </>
      )}
      {"page" in result && legacy.length > 0 ? (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">HTTP check-in and sample hosts</h2>
          <DeviceTable devices={legacy} />
        </section>
      ) : null}
    </div>
  );
}

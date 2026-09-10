import { DeviceTable } from "@/components/device-table";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadFleet } from "@/lib/mtls-agents";

export const dynamic = "force-dynamic";

export default async function DevicesPage() {
  const store = await ensureStore();
  const devices = (await loadFleet(store.devices)).map(publicDevice);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Hosts</h1>
        <p className="mt-1 text-muted-foreground">
          HTTP inventory agents and mTLS gRPC agents. Go agents report packages, patches, and
          file hashes over ReportInventory.
        </p>
      </div>
      <DeviceTable devices={devices} />
    </div>
  );
}

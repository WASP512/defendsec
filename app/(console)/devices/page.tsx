import { DeviceTable } from "@/components/device-table";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadMtlsDevices, mergeDevices } from "@/lib/mtls-agents";

export const dynamic = "force-dynamic";

export default async function DevicesPage() {
  const store = await ensureStore();
  const devices = mergeDevices(store.devices, await loadMtlsDevices()).map(publicDevice);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Hosts</h1>
        <p className="mt-1 text-muted-foreground">
          JSON-agent hosts plus mTLS gRPC agents. Click a hostname for inventory when the Python
          agent has reported it; Phase 1 Go agents show presence only.
        </p>
      </div>
      <DeviceTable devices={devices} />
    </div>
  );
}

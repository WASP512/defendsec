import { DeviceTable } from "@/components/device-table";
import { ensureStore, publicDevice } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function DevicesPage() {
  const store = await ensureStore();
  const devices = store.devices.map(publicDevice);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Hosts</h1>
        <p className="mt-1 text-muted-foreground">
          Every enrolled or sample machine. Click a hostname for inventory, software, and policy
          results.
        </p>
      </div>
      <DeviceTable devices={devices} />
    </div>
  );
}

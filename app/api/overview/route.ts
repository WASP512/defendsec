import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadMtlsDevices, mergeDevices } from "@/lib/mtls-agents";
import { isOnline } from "@/lib/policies";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    const fleet = mergeDevices(store.devices, await loadMtlsDevices());
    const devices = fleet.map(publicDevice);
    const online = fleet.filter((d) => isOnline(d)).length;
    return NextResponse.json({
      total: fleet.length,
      online,
      offline: fleet.length - online,
      samples: fleet.filter((d) => d.sample).length,
      live: fleet.filter((d) => !d.sample).length,
      platforms: {
        darwin: fleet.filter((d) => d.platform === "darwin").length,
        windows: fleet.filter((d) => d.platform === "windows").length,
        linux: fleet.filter((d) => d.platform === "linux").length,
      },
      devices,
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

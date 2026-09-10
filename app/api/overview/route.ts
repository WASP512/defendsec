import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { isOnline } from "@/lib/policies";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    const devices = store.devices.map(publicDevice);
    const online = store.devices.filter((d) => isOnline(d)).length;
    return NextResponse.json({
      total: store.devices.length,
      online,
      offline: store.devices.length - online,
      samples: store.devices.filter((d) => d.sample).length,
      live: store.devices.filter((d) => !d.sample).length,
      platforms: {
        darwin: store.devices.filter((d) => d.platform === "darwin").length,
        windows: store.devices.filter((d) => d.platform === "windows").length,
        linux: store.devices.filter((d) => d.platform === "linux").length,
      },
      devices,
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

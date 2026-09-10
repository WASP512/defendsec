import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { loadMtlsDevices, mergeDevices } from "@/lib/mtls-agents";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    const devices = mergeDevices(store.devices, await loadMtlsDevices());
    return NextResponse.json({
      devices: devices.map(publicDevice),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

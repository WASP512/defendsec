import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    return NextResponse.json({
      devices: store.devices.map(publicDevice),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

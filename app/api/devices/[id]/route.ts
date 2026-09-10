import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";
import { evaluateDevice } from "@/lib/policies";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const { id } = await params;
    const store = await ensureStore();
    const device = store.devices.find((d) => d.id === id);
    if (!device) {
      return NextResponse.json({ error: "Device not found" }, { status: 404 });
    }
    return NextResponse.json({
      device: publicDevice(device),
      policies: evaluateDevice(device, store.fimEvents, store.triages),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

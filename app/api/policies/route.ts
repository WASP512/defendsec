import { NextResponse } from "next/server";
import { ensureStore } from "@/lib/store";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { policySummary } from "@/lib/policies";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    const fleet = await loadFleet(store.devices);
    return NextResponse.json({
      policies: policySummary(fleet, [...(await loadMtlsFimEvents()), ...store.fimEvents], store.triages),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

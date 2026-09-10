import { NextResponse } from "next/server";
import { ensureStore } from "@/lib/store";
import { policySummary } from "@/lib/policies";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    return NextResponse.json({
      policies: policySummary(store.devices, store.fimEvents, store.triages),
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

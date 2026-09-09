import { NextResponse } from "next/server";
import { ensureStore } from "@/lib/store";
import { policySummary } from "@/lib/policies";

export const runtime = "nodejs";

export async function GET() {
  const store = await ensureStore();
  return NextResponse.json({
    policies: policySummary(store.devices, store.fimEvents, store.triages),
  });
}

import { NextResponse } from "next/server";
import { ensureStore, publicDevice } from "@/lib/store";

export const runtime = "nodejs";

export async function GET() {
  const store = await ensureStore();
  return NextResponse.json({
    devices: store.devices.map(publicDevice),
  });
}

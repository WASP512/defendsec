import { NextResponse } from "next/server";
import { sampleFleet } from "@/lib/demo";
import { clearSampleFleet, replaceSampleFleet } from "@/lib/store";

export const runtime = "nodejs";

export async function POST() {
  const store = await replaceSampleFleet(sampleFleet());
  return NextResponse.json({
    ok: true,
    samples: store.devices.filter((d) => d.sample).length,
  });
}

export async function DELETE() {
  const store = await clearSampleFleet();
  return NextResponse.json({
    ok: true,
    remaining: store.devices.length,
  });
}

import { NextResponse } from "next/server";
import { sampleFleet } from "@/lib/demo";
import { clearSampleFleet, replaceSampleFleet } from "@/lib/store";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await replaceSampleFleet(sampleFleet());
    return NextResponse.json({
      ok: true,
      samples: store.devices.filter((d) => d.sample).length,
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

export async function DELETE(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await clearSampleFleet();
    return NextResponse.json({
      ok: true,
      remaining: store.devices.length,
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

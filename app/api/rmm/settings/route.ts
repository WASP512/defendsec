import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Choose the one RMM site this instance reads. apid checks it against the RMM's
// live site list, validates the threshold and records who chose it.
export async function PUT(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  return forwardToApid(request, "/v1/rmm/settings", { method: "PUT", body });
}

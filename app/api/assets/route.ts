import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Declare an asset. apid validates and normalises it and records who declared it.
export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  return forwardToApid(request, "/v1/assets", { method: "POST", body });
}

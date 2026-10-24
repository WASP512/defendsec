import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Save the Autotask company this instance opens tickets in and how those tickets
// look. apid validates every field, records who changed it, and refuses mode "live"
// without a dry run for exactly these settings behind it. No credential is accepted
// here: the API user's secret and integration code are files on the server.
export async function PUT(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  return forwardToApid(request, "/v1/autotask/settings", { method: "PUT", body });
}

import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Save the Google Workspace administrator this instance reads as and how the domain is
// judged. apid validates every field and records who changed it. No credential is
// accepted here: the service account's key is a file on the server.
export async function PUT(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  return forwardToApid(request, "/v1/identity/google/settings", { method: "PUT", body });
}

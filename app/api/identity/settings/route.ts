import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Save the Microsoft 365 tenant this instance reads and how it is judged. apid
// validates every field and records who changed it. No credential is accepted
// here: the certificate or secret is a file on the server.
export async function PUT(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  return forwardToApid(request, "/v1/identity/m365/settings", { method: "PUT", body });
}

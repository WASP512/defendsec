import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { getApidAuthToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";

export const runtime = "nodejs";

// The RMM's live site list, for the picker. Admin only: it spends request quota
// that the whole RMM account shares, and it names clients.
export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const token = await getApidAuthToken(request);
    const response = await fetch(new URL("/v1/rmm/sites", APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { error: text.trim() || `Request failed (${response.status})` };
    }
    return NextResponse.json(parsed, { status: response.status });
  } catch {
    return NextResponse.json({ error: "The control plane could not be reached." }, { status: 502 });
  }
}

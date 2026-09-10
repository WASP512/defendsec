import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  const { id } = await params;
  let reason = "revoked from console";
  try {
    const incoming = (await request.json()) as { reason?: string };
    if (incoming.reason?.trim()) {
      reason = incoming.reason.trim();
    }
  } catch {
    // empty body is fine
  }

  try {
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/revoke", APID_ADMIN_URL), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ deviceId: id, reason }),
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return NextResponse.json(
      { error: "Control plane is not reachable on 127.0.0.1:47264. Start defendsec-apid." },
      { status: 503 },
    );
  }
}

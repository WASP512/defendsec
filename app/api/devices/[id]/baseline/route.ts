import { NextResponse } from "next/server";
import { acceptFimBaseline } from "@/lib/store";
import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const { id } = await params;
    const result = await acceptFimBaseline(id);
    if (result.ok) {
      return NextResponse.json({ ok: true });
    }
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/baseline", APID_ADMIN_URL), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ deviceId: id }),
    });
    if (response.ok) {
      return NextResponse.json({ ok: true });
    }
    return NextResponse.json({ error: "Device not found" }, { status: 404 });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

import { NextResponse } from "next/server";
import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  const { id } = await params;
  try {
    const token = await getAdminToken();
    const url = new URL("/v1/commands", APID_ADMIN_URL);
    url.searchParams.set("deviceId", id);
    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
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

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  const { id } = await params;
  try {
    const incoming = (await request.json()) as { type?: string; payload?: unknown };
    const token = await getAdminToken();
    const response = await fetch(new URL("/v1/commands", APID_ADMIN_URL), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        deviceId: id,
        type: incoming.type,
        payload: incoming.payload ?? {},
      }),
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    if (error instanceof SyntaxError) {
      return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
    }
    return NextResponse.json(
      { error: "Control plane is not reachable on 127.0.0.1:47264. Start defendsec-apid." },
      { status: 503 },
    );
  }
}

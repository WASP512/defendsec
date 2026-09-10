import { NextResponse } from "next/server";
import { unauthorizedIfNotAuthenticated } from "@/lib/api-auth";
import { getApidAuthToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAuthenticated(request);
  if (denied) return denied;

  const channel = new URL(request.url).searchParams.get("channel") || "stable";
  try {
    const token = await getApidAuthToken(request);
    const url = new URL("/v1/agent-releases", APID_ADMIN_URL);
    url.searchParams.set("channel", channel);
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

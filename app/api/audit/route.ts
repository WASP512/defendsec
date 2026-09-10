import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { databaseURL, listAudit } from "@/lib/pg";
import { getAdminToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  const limit = Number(new URL(request.url).searchParams.get("limit") || "100");

  if (databaseURL()) {
    try {
      const events = await listAudit(Number.isFinite(limit) ? limit : 100);
      return NextResponse.json({ source: "postgres", events });
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "postgres audit failed" },
        { status: 500 },
      );
    }
  }

  try {
    const token = await getAdminToken();
    const url = new URL("/v1/audit", APID_ADMIN_URL);
    url.searchParams.set("limit", String(limit || 100));
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
      {
        error:
          "Audit requires Postgres (DATABASE_URL) or a running defendsec-apid admin listener on :47264.",
      },
      { status: 503 },
    );
  }
}

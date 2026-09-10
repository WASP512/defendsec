import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin, unauthorizedIfNotAuthenticated } from "@/lib/api-auth";
import { databaseURL } from "@/lib/pg";
import {
  listAlerts,
  listAlertsFromApid,
  updateAlertStatus,
  updateAlertStatusViaApid,
  type AlertStatus,
} from "@/lib/alerts";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAuthenticated(request);
  if (denied) return denied;

  const url = new URL(request.url);
  const filters = {
    status: url.searchParams.get("status") ?? "",
    kind: url.searchParams.get("kind") ?? "",
    deviceId: url.searchParams.get("deviceId") ?? "",
    limit: Number(url.searchParams.get("limit") || "200"),
  };

  if (databaseURL()) {
    try {
      const alerts = await listAlerts(filters);
      return NextResponse.json({ source: "postgres", alerts });
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "postgres alerts failed" },
        { status: 500 },
      );
    }
  }

  try {
    const alerts = await listAlertsFromApid(filters);
    return NextResponse.json({ source: "apid", alerts });
  } catch {
    return NextResponse.json(
      {
        error:
          "Alerts require Postgres (DATABASE_URL) or a running defendsec-apid admin listener on :47264.",
      },
      { status: 503 },
    );
  }
}

export async function PATCH(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  let body: { id?: string; status?: AlertStatus };
  try {
    body = (await request.json()) as { id?: string; status?: AlertStatus };
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  const id = body.id?.trim();
  const status = body.status;
  if (!id || !status) {
    return NextResponse.json({ error: "id and status required" }, { status: 400 });
  }
  if (!["open", "acknowledged", "resolved", "suppressed"].includes(status)) {
    return NextResponse.json({ error: "invalid status" }, { status: 400 });
  }

  if (databaseURL()) {
    try {
      const ok = await updateAlertStatus(id, status);
      if (!ok) return NextResponse.json({ error: "alert not found" }, { status: 404 });
      return NextResponse.json({ ok: true });
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "postgres update failed" },
        { status: 500 },
      );
    }
  }

  try {
    await updateAlertStatusViaApid(id, status);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "apid update failed" },
      { status: 503 },
    );
  }
}

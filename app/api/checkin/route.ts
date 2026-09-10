import { NextResponse } from "next/server";
import { checkin } from "@/lib/store";
import { storeErrorResponse } from "@/lib/api-auth";
import type { CheckinPayload } from "@/lib/types";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: CheckinPayload;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.nodeKey) {
    return NextResponse.json({ error: "nodeKey required" }, { status: 400 });
  }
  try {
    const result = await checkin(body);
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: 401 });
    }
    return NextResponse.json({ ok: true, deviceId: result.deviceId });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

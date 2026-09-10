import { NextResponse } from "next/server";
import { enrollDevice } from "@/lib/store";
import { storeErrorResponse } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: { enrollSecret?: string; hostname?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const hostname = (body.hostname ?? "").trim() || "unknown-host";
  const secret = body.enrollSecret ?? "";
  try {
    const result = await enrollDevice(secret, hostname);
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: 401 });
    }
    return NextResponse.json({
      nodeKey: result.nodeKey,
      deviceId: result.deviceId,
      existing: result.existing,
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

import { NextResponse } from "next/server";
import { setTriage } from "@/lib/store";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: { key?: string; status?: "open" | "acknowledged" };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.key || (body.status !== "open" && body.status !== "acknowledged")) {
    return NextResponse.json({ error: "key and status required" }, { status: 400 });
  }
  const triages = await setTriage(body.key, body.status);
  return NextResponse.json({ ok: true, triages });
}

import { NextResponse } from "next/server";
import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

function assetPath(id: string, suffix = "") {
  return /^[1-9][0-9]*$/.test(id) ? `/v1/assets/${id}${suffix}` : null;
}

// Give or withdraw the "I am authorised to test this asset" confirmation.
export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  const path = assetPath((await params).id, "/authorise");
  if (!path) return NextResponse.json({ error: "Invalid asset id" }, { status: 400 });
  let body: { authorised?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (typeof body.authorised !== "boolean") {
    return NextResponse.json({ error: "authorised must be true or false" }, { status: 400 });
  }
  return forwardToApid(request, path, { method: "POST", body: { authorised: body.authorised } });
}

// Stop scanning an asset and hide it. Its findings stay as evidence.
export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  const path = assetPath((await params).id);
  if (!path) return NextResponse.json({ error: "Invalid asset id" }, { status: 400 });
  return forwardToApid(request, path, { method: "DELETE" });
}

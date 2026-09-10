import { NextResponse } from "next/server";
import { acceptFimBaseline } from "@/lib/store";
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
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: 404 });
    }
    return NextResponse.json({ ok: true });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

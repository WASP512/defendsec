import { NextResponse } from "next/server";
import { ensureStore, rotateEnrollSecret } from "@/lib/store";
import { storeErrorResponse, unauthorizedIfNotAdmin } from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const store = await ensureStore();
    return NextResponse.json({ enrollSecret: store.enrollSecret });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  try {
    const enrollSecret = await rotateEnrollSecret();
    return NextResponse.json({ enrollSecret });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

import { NextResponse } from "next/server";
import { ensureStore } from "@/lib/store";
import { getApidAuthToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";
import {
  storeErrorResponse,
  unauthorizedIfNotAdmin,
  unauthorizedIfNotAuthenticated,
} from "@/lib/api-auth";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAuthenticated(request);
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
    const response = await fetch(new URL("/v1/enroll-secret", APID_ADMIN_URL), {
      method: "POST",
      headers: { Authorization: `Bearer ${await getApidAuthToken(request)}` },
      cache: "no-store",
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "Content-Type": response.headers.get("content-type") ?? "application/json" },
    });
  } catch (error) {
    return storeErrorResponse(error);
  }
}

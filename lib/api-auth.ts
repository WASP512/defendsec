import { NextResponse } from "next/server";
import { isAdminRequest, isAuthenticatedRequest } from "@/lib/auth";
import { StoreCorruptError } from "@/lib/store";

export async function unauthorizedIfNotAuthenticated(request: Request) {
  if (await isAuthenticatedRequest(request)) return null;
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

export async function unauthorizedIfNotAdmin(request: Request) {
  if (await isAdminRequest(request)) return null;
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}

export function storeErrorResponse(error: unknown) {
  if (error instanceof StoreCorruptError) {
    return NextResponse.json({ error: error.message }, { status: 503 });
  }
  throw error;
}

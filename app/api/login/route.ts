import { NextResponse } from "next/server";
import { ADMIN_COOKIE, adminCookieOptions, getAdminToken, safeEqual } from "@/lib/auth";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: { token?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const expected = await getAdminToken();
  if (!body.token || !safeEqual(body.token, expected)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const response = NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, expected, adminCookieOptions());
  return response;
}

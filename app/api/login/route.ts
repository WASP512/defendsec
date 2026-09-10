import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  adminCookieOptions,
  getAdminToken,
  getViewerToken,
  safeEqual,
} from "@/lib/auth";

export const runtime = "nodejs";

async function readToken(request: Request) {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = (await request.json()) as { token?: string };
    return { token: body.token ?? "", mode: "json" as const };
  }
  const form = await request.formData();
  return { token: String(form.get("token") ?? ""), mode: "form" as const };
}

export async function POST(request: Request) {
  let parsed: { token: string; mode: "json" | "form" };
  try {
    parsed = await readToken(request);
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  const admin = await getAdminToken();
  const viewer = getViewerToken();
  const ok =
    parsed.token &&
    (safeEqual(parsed.token, admin) || (viewer !== "" && safeEqual(parsed.token, viewer)));
  if (!ok) {
    if (parsed.mode === "form") {
      return NextResponse.redirect(new URL("/login?error=1", request.url), 303);
    }
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (parsed.mode === "form") {
    const response = NextResponse.redirect(new URL("/", request.url), 303);
    response.cookies.set(ADMIN_COOKIE, parsed.token, adminCookieOptions());
    return response;
  }
  const response = NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, parsed.token, adminCookieOptions());
  return response;
}

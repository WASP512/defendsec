import { ADMIN_COOKIE, adminCookieOptions } from "@/lib/auth";
import { redirectTo } from "@/lib/http";

export const runtime = "nodejs";

export async function POST() {
  const response = redirectTo("/login");
  response.cookies.set(ADMIN_COOKIE, "", { ...adminCookieOptions(), maxAge: 0 });
  return response;
}

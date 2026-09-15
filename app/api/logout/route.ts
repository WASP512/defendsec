import { cookies } from "next/headers";

import { ADMIN_COOKIE, adminCookieOptions } from "@/lib/auth";
import { redirectTo } from "@/lib/http";
import { apidLogout } from "@/lib/identity";

export const runtime = "nodejs";

export async function POST() {
  // Clearing the cookie alone would leave the session valid in the control
  // plane until it expired, so anyone holding a copy of the token could keep
  // using it. Revoke it server-side too.
  const jar = await cookies();
  const token = jar.get(ADMIN_COOKIE)?.value ?? "";
  await apidLogout(token);

  const response = redirectTo("/login");
  response.cookies.set(ADMIN_COOKIE, "", { ...adminCookieOptions(), maxAge: 0 });
  return response;
}

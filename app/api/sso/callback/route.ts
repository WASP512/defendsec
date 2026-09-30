import { cookies } from "next/headers";

import { ADMIN_COOKIE, adminCookieOptions } from "@/lib/auth";
import { redirectTo } from "@/lib/http";
import { apidSSOFinish } from "@/lib/identity";
import { loginRateLimitKey } from "@/lib/rate-limit";
import { decodeFlow, SSO_COOKIE, stateMatches } from "@/lib/sso-flow";

export const runtime = "nodejs";

function fail(message: string) {
  const res = redirectTo("/login?ssoError=" + encodeURIComponent(message));
  res.cookies.delete(SSO_COOKIE);
  return res;
}

// The identity provider redirects here. The state is checked against the
// cookie before anything else, then the control plane does the exchange,
// verification and role mapping.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const idpError = url.searchParams.get("error");
  if (idpError) {
    return fail(url.searchParams.get("error_description") || `The identity provider returned ${idpError}.`);
  }

  const jar = await cookies();
  const flow = decodeFlow(jar.get(SSO_COOKIE)?.value);
  if (!flow || !stateMatches(flow.state, url.searchParams.get("state"))) {
    return fail("This sign-in could not be matched to one started in this browser. Start again.");
  }
  const code = url.searchParams.get("code");
  if (!code) return fail("The identity provider returned no authorization code.");

  let result;
  try {
    result = await apidSSOFinish({
      code,
      verifier: flow.verifier,
      nonce: flow.nonce,
      clientAddress: loginRateLimitKey(request),
    });
  } catch {
    return fail("The control plane is not reachable.");
  }
  if ("error" in result) return fail(result.error);

  const res = redirectTo("/");
  res.cookies.delete(SSO_COOKIE);
  res.cookies.set(ADMIN_COOKIE, result.token, adminCookieOptions());
  return res;
}

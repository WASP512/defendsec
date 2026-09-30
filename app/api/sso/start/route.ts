import { adminCookieOptions } from "@/lib/auth";
import { redirectTo } from "@/lib/http";
import { apidSSOStart } from "@/lib/identity";
import { encodeFlow, SSO_COOKIE, SSO_COOKIE_MAX_AGE } from "@/lib/sso-flow";

export const runtime = "nodejs";

// Begins single sign-on: asks the control plane for a flow, keeps its secrets
// in a short httpOnly cookie, and sends the browser to the identity provider.
export async function GET() {
  let flow;
  try {
    flow = await apidSSOStart();
  } catch {
    return redirectTo("/login?ssoError=" + encodeURIComponent("The control plane is not reachable."));
  }
  if ("error" in flow) {
    return redirectTo("/login?ssoError=" + encodeURIComponent(flow.error));
  }
  const response = redirectTo(flow.authUrl);
  response.cookies.set(
    SSO_COOKIE,
    encodeFlow({ state: flow.state, nonce: flow.nonce, verifier: flow.verifier }),
    // Lax, not Strict: the IdP's redirect back is a cross-site top-level
    // navigation, and Strict would drop the cookie exactly there.
    { ...adminCookieOptions(), sameSite: "lax", maxAge: SSO_COOKIE_MAX_AGE },
  );
  return response;
}

import { ADMIN_COOKIE, adminCookieOptions } from "@/lib/auth";
import { redirectTo } from "@/lib/http";
import { apidSetup, IdentityUnavailableError } from "@/lib/identity";
import { cleanInvite, validateSetup } from "@/lib/login-state";
import { isRateLimited, loginRateLimitKey, recordFailedAttempt } from "@/lib/rate-limit";

export const runtime = "nodejs";

// First-run setup: create the first administrator without the shared token.
//
// The console decides nothing here. The control plane owns whether setup is
// open — no accounts yet, and inside the window after it started — and
// creates the account under a lock so two people cannot both claim it.

function back(message: string, invite = "") {
  const inv = invite ? `&invite=${encodeURIComponent(invite)}` : "";
  return redirectTo(`/login?setupError=${encodeURIComponent(message)}${inv}`);
}

export async function POST(request: Request) {
  const key = `setup:${loginRateLimitKey(request)}`;
  if (isRateLimited(key).limited) {
    return back("Too many attempts. Wait a few minutes and try again.");
  }

  const form = await request.formData();
  const username = String(form.get("username") ?? "").trim();
  const displayName = String(form.get("displayName") ?? "").trim();
  const password = String(form.get("password") ?? "");
  const confirm = String(form.get("confirm") ?? "");
  const invite = cleanInvite(String(form.get("invite") ?? ""));

  const invalid = validateSetup({ username, password, confirm });
  if (invalid) {
    recordFailedAttempt(key);
    return back(invalid, invite);
  }

  let outcome;
  try {
    outcome = await apidSetup({
      username,
      displayName,
      password,
      clientAddress: loginRateLimitKey(request),
      invite,
    });
  } catch (err) {
    if (err instanceof IdentityUnavailableError) return back(err.message, invite);
    throw err;
  }
  if (!outcome.ok) {
    recordFailedAttempt(key);
    return back(outcome.error, invite);
  }
  if (!outcome.token) {
    // Created but not signed in; the ordinary form will work now.
    return redirectTo("/login?created=1");
  }

  const response = redirectTo("/");
  response.cookies.set(ADMIN_COOKIE, outcome.token, adminCookieOptions());
  return response;
}

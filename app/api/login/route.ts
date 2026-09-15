import { NextResponse } from "next/server";
import {
  ADMIN_COOKIE,
  adminCookieOptions,
  getAdminToken,
  getViewerToken,
  safeEqual,
} from "@/lib/auth";
import { redirectTo } from "@/lib/http";
import { apidLogin, IdentityUnavailableError } from "@/lib/identity";
import { clearAttempts, isRateLimited, loginRateLimitKey, recordFailedAttempt } from "@/lib/rate-limit";

export const runtime = "nodejs";

// Sign-in accepts an account username and password, with a second factor when
// one is enrolled. The shared admin and viewer tokens still work: they are how
// the first account gets created, and how the installers and scripts reach a
// fresh install. Actions taken under one are recorded as unattributed, because
// they genuinely cannot be traced to a person (roadmap 1.0).

type Credentials = {
  username: string;
  password: string;
  totpCode: string;
  token: string;
  mode: "json" | "form";
};

async function readCredentials(request: Request): Promise<Credentials> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = (await request.json()) as Partial<Record<keyof Credentials, string>>;
    return {
      username: body.username ?? "",
      password: body.password ?? "",
      totpCode: body.totpCode ?? "",
      token: body.token ?? "",
      mode: "json",
    };
  }
  const form = await request.formData();
  return {
    username: String(form.get("username") ?? ""),
    password: String(form.get("password") ?? ""),
    totpCode: String(form.get("totpCode") ?? ""),
    token: String(form.get("token") ?? ""),
    mode: "form",
  };
}

/** A form post fails back to the login page; JSON callers get a status. */
function fail(
  creds: Credentials,
  status: number,
  error: string,
  query: string,
  extra: Record<string, unknown> = {},
) {
  if (creds.mode === "form") return redirectTo(`/login?${query}`);
  return NextResponse.json({ error, ...extra }, { status });
}

function succeed(creds: Credentials, token: string) {
  const response =
    creds.mode === "form" ? redirectTo("/") : NextResponse.json({ ok: true });
  response.cookies.set(ADMIN_COOKIE, token, adminCookieOptions());
  return response;
}

export async function POST(request: Request) {
  const rateLimitKey = loginRateLimitKey(request);
  const { limited, retryAfterSeconds } = isRateLimited(rateLimitKey);
  if (limited) {
    return NextResponse.json(
      { error: "Too many attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfterSeconds) } },
    );
  }

  let creds: Credentials;
  try {
    creds = await readCredentials(request);
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }

  // Account sign-in.
  if (creds.username && creds.password) {
    let outcome;
    try {
      outcome = await apidLogin(creds.username, creds.password, creds.totpCode);
    } catch (err) {
      if (err instanceof IdentityUnavailableError) {
        return fail(creds, 503, err.message, "error=unavailable");
      }
      throw err;
    }

    if (outcome.ok) {
      clearAttempts(rateLimitKey);
      return succeed(creds, outcome.token);
    }
    if ("totpRequired" in outcome) {
      // Not a failed attempt: the password was right and a code is now
      // needed, so it must not count toward the rate limit or the operator
      // could lock themselves out mid-login.
      return fail(creds, 401, "second factor required", "totp=1", { totpRequired: true });
    }
    recordFailedAttempt(rateLimitKey);
    if ("locked" in outcome) {
      return fail(creds, 429, "account temporarily locked", "error=locked");
    }
    return fail(creds, 401, "invalid credentials", "error=1");
  }

  // Shared bootstrap token.
  if (creds.token) {
    const admin = await getAdminToken();
    const viewer = getViewerToken();
    const ok =
      safeEqual(creds.token, admin) || (viewer !== "" && safeEqual(creds.token, viewer));
    if (ok) {
      clearAttempts(rateLimitKey);
      return succeed(creds, creds.token);
    }
    recordFailedAttempt(rateLimitKey);
    return fail(creds, 401, "Unauthorized", "error=1");
  }

  recordFailedAttempt(rateLimitKey);
  return fail(creds, 400, "username and password, or a token, are required", "error=1");
}

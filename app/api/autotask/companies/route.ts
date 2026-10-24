import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// A company name search (at most 25 active companies), to find the id the settings
// keep. The id, not the name, is what is saved.
export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  const q = new URL(request.url).searchParams.get("q") ?? "";
  return forwardToApid(request, `/v1/autotask/companies?q=${encodeURIComponent(q)}`, { method: "GET" });
}

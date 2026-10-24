import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Autotask's live picklists (queues, statuses, priorities, issue types, note types)
// and the chosen company, for the settings form. Reading them spends a few requests
// of the database's hourly allowance, so only an administrator can ask.
export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  return forwardToApid(request, "/v1/autotask/picklists", { method: "GET" });
}

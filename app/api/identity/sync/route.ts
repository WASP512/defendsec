import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Read the tenant now. The page does not wait for the whole read: apid answers
// 202 and reads in the background, and the page shows the result when it
// reloads. A read that is already running answers 409.
export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  return forwardToApid(request, "/v1/identity/m365/sync", { method: "POST", body: { wait: false } });
}

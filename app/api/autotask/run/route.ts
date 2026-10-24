import { unauthorizedIfNotAdmin } from "@/lib/api-auth";
import { forwardToApid } from "@/lib/surface";

export const runtime = "nodejs";

// Reconcile the tickets now. {dryRun: true} (the default) shows the exact tickets
// and changes nothing; {dryRun: false} needs the settings in live mode. The page
// does not wait for a whole run: apid answers 202 and runs in the background, and
// the page shows the result when it reloads. A run that is already going answers 409.
export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;
  let dryRun = true;
  try {
    const body = (await request.json()) as { dryRun?: unknown };
    if (body.dryRun === false) dryRun = false;
  } catch {
    // no body: a dry run
  }
  return forwardToApid(request, "/v1/autotask/run", { method: "POST", body: { dryRun, wait: false } });
}

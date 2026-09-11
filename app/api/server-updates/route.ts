import { mkdir, rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { unauthorizedIfNotAdmin, unauthorizedIfNotAuthenticated } from "@/lib/api-auth";
import { dataDir } from "@/lib/data-paths";
import { getServerUpdateState } from "@/lib/server-updates";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAuthenticated(request);
  if (denied) return denied;
  return Response.json(await getServerUpdateState(), {
    headers: { "Cache-Control": "no-store" },
  });
}

export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  let requested: { version?: string };
  try {
    requested = (await request.json()) as { version?: string };
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const state = await getServerUpdateState();
  if (!state.updateAvailable || !state.latestVersion || !state.tag) {
    return Response.json({ error: "No server update is available" }, { status: 409 });
  }
  if (requested.version !== state.latestVersion) {
    return Response.json({ error: "Release changed; refresh and review the new version" }, { status: 409 });
  }
  if (!state.canApply) {
    return Response.json({ error: state.unavailableReason || "One-click updates are not configured" }, { status: 503 });
  }
  if (state.status.state === "downloading" || state.status.state === "installing") {
    return Response.json({ error: "A server update is already running" }, { status: 409 });
  }

  const directory = dataDir();
  const requestPath = join(directory, "update-request.json");
  const temporaryPath = `${requestPath}.tmp`;
  await mkdir(directory, { recursive: true });
  try {
    await writeFile(
      join(directory, "update-status.json"),
      `${JSON.stringify({
        state: "downloading",
        message: "The approved release is waiting for the system updater.",
        version: state.latestVersion,
        updatedAt: new Date().toISOString(),
      })}\n`,
      { encoding: "utf8", mode: 0o644 },
    );
    await writeFile(
      temporaryPath,
      `${JSON.stringify({
        repo: state.repo,
        tag: state.tag,
        version: state.latestVersion,
        requestedAt: new Date().toISOString(),
      })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    // Creating this fixed path is the only trigger. The root-owned systemd
    // path unit observes it and starts the updater outside the console sandbox.
    await rename(temporaryPath, requestPath);
  } catch {
    await unlink(temporaryPath).catch(() => undefined);
    await unlink(requestPath).catch(() => undefined);
    return Response.json(
      { error: "Could not initialize update status." },
      { status: 503 },
    );
  }

  return Response.json(
    { ok: true, state: "downloading", version: state.latestVersion },
    { status: 202 },
  );
}


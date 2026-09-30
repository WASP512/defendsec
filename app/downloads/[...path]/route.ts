import { readFileSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { NextResponse } from "next/server";
import { dataPath } from "@/lib/data-paths";
import { AGENT_DOWNLOADS } from "@/lib/agent-commands";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";



const ALLOWED = new Set<string>(AGENT_DOWNLOADS);

function downloadsDir(): string {
  return (
    process.env.DEFENDSEC_DOWNLOADS_DIR?.trim() ||
    dataPath("downloads")
  );
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path: parts } = await params;
  if (!parts || parts.length !== 1) {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  const name = basename(parts[0] ?? "");
  if (!ALLOWED.has(name)) {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  const full = join(downloadsDir(), name);
  if (!existsSync(full) || !statSync(full).isFile()) {
    return NextResponse.json(
      { error: "artifact missing — run server install / publish agent downloads" },
      { status: 404 },
    );
  }
  const body = readFileSync(full);
  const contentType =
    name.endsWith(".sh") || name.endsWith(".ps1") || name === "SHA256SUMS"
      ? "text/plain; charset=utf-8"
      : name.endsWith(".msi")
        ? "application/x-msi"
        : "application/octet-stream";
  return new NextResponse(body, {
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": `attachment; filename="${name}"`,
      "Cache-Control": "no-store",
      "Content-Length": String(body.byteLength),
    },
  });
}

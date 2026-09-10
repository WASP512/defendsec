import { readFileSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED = new Set([
  "install-agent.sh",
  "SHA256SUMS",
  "defendsec-agentd-linux-amd64",
  "defendsec-agentd-linux-arm64",
]);

function downloadsDir(): string {
  return (
    process.env.DEFENDSEC_DOWNLOADS_DIR?.trim() ||
    join(process.cwd(), "data", "downloads")
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
    name.endsWith(".sh") || name === "SHA256SUMS"
      ? "text/plain; charset=utf-8"
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

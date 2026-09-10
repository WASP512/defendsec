import { NextResponse } from "next/server";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { unauthorizedIfNotAdmin, unauthorizedIfNotAuthenticated } from "@/lib/api-auth";
import { getApidAuthToken } from "@/lib/auth";
import { APID_ADMIN_URL } from "@/lib/commands";
import { dataPath } from "@/lib/data-paths";
import { databaseURL, query } from "@/lib/pg";

export const runtime = "nodejs";

const FALLBACK_PATH = dataPath("saved-queries.json");

type SavedQuery = {
  id: string;
  name: string;
  query: string;
  createdAt: string;
};

async function listFromFile(): Promise<SavedQuery[]> {
  try {
    const raw = await readFile(FALLBACK_PATH, "utf8");
    const parsed = JSON.parse(raw) as { queries?: SavedQuery[] };
    return parsed.queries ?? [];
  } catch {
    return [];
  }
}

async function appendToFile(name: string, queryText: string): Promise<SavedQuery> {
  const rec: SavedQuery = {
    id: randomBytes(8).toString("hex"),
    name,
    query: queryText,
    createdAt: new Date().toISOString(),
  };
  const existing = await listFromFile();
  existing.unshift(rec);
  await mkdir(dirname(FALLBACK_PATH), { recursive: true });
  await writeFile(
    FALLBACK_PATH,
    JSON.stringify({ updatedAt: new Date().toISOString(), queries: existing.slice(0, 200) }, null, 2),
    "utf8",
  );
  return rec;
}

export async function GET(request: Request) {
  const denied = await unauthorizedIfNotAuthenticated(request);
  if (denied) return denied;

  if (databaseURL()) {
    try {
      const rows = await query<{ id: string; name: string; query: string; created_at: Date }>(
        `SELECT id, name, query, created_at FROM saved_queries ORDER BY created_at DESC`,
      );
      return NextResponse.json({
        source: "postgres",
        queries: rows.map((row) => ({
          id: row.id,
          name: row.name,
          query: row.query,
          createdAt: new Date(row.created_at).toISOString(),
        })),
      });
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "postgres saved queries failed" },
        { status: 500 },
      );
    }
  }

  try {
    const token = await getApidAuthToken(request);
    const response = await fetch(new URL("/v1/saved-queries", APID_ADMIN_URL), {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    const queries = await listFromFile();
    return NextResponse.json({ source: "file", queries });
  }
}

export async function POST(request: Request) {
  const denied = await unauthorizedIfNotAdmin(request);
  if (denied) return denied;

  const incoming = (await request.json()) as { name?: string; query?: string };
  const name = incoming.name?.trim() ?? "";
  const queryText = incoming.query?.trim().toLowerCase() ?? "";
  if (!name || !queryText) {
    return NextResponse.json({ error: "name and query required" }, { status: 400 });
  }

  if (databaseURL()) {
    try {
      const id = randomBytes(8).toString("hex");
      await query(`INSERT INTO saved_queries (id, name, query) VALUES ($1,$2,$3)`, [id, name, queryText]);
      return NextResponse.json({ id, name, query: queryText });
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "postgres saved query create failed" },
        { status: 500 },
      );
    }
  }

  try {
    const token = await getApidAuthToken();
    const response = await fetch(new URL("/v1/saved-queries", APID_ADMIN_URL), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, query: queryText }),
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    const rec = await appendToFile(name, queryText);
    return NextResponse.json(rec);
  }
}

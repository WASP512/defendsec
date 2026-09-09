import { NextResponse } from "next/server";
import { ensureStore, rotateEnrollSecret } from "@/lib/store";

export const runtime = "nodejs";

export async function GET() {
  const store = await ensureStore();
  return NextResponse.json({ enrollSecret: store.enrollSecret });
}

export async function POST() {
  const enrollSecret = await rotateEnrollSecret();
  return NextResponse.json({ enrollSecret });
}

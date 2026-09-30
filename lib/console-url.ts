import { headers } from "next/headers";

// The console's public URL as a browser reached it, or as configured.
export async function consoleURL(): Promise<string> {
  const configured = process.env.DEFENDSEC_PUBLIC_CONSOLE_URL?.trim().replace(/\/+$/, "");
  if (configured) return configured;
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "127.0.0.1:47261";
  const proto = headerList.get("x-forwarded-proto") ?? "http";
  return `${proto}://${host}`;
}

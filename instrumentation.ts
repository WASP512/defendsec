// Runs once when the Node.js server process starts handling requests
// (Next.js instrumentation hook) — not on every request. Surfaces the
// HTTP-by-default tradeoff in the logs instead of leaving it as something
// operators only find by reading docs/OPERATIONS.md. Doesn't change any
// behavior or block startup.
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (process.env.NODE_ENV !== "production") return;

  const publicUrl = process.env.DEFENDSEC_PUBLIC_CONSOLE_URL?.trim() ?? "";
  const hasHttpsPublicUrl = publicUrl.toLowerCase().startsWith("https://");
  if (hasHttpsPublicUrl) return;

  console.warn(
    "[defendsec] No HTTPS DEFENDSEC_PUBLIC_CONSOLE_URL is configured, so this console " +
      "is reachable only over plain HTTP (or an unconfirmed proxy). The admin/viewer " +
      "session cookie either travels unencrypted, or — if DEFENDSEC_COOKIE_SECURE=true — " +
      "browsers will refuse to store it here at all. Fine on a trusted, isolated LAN. " +
      "Before exposing this console anywhere else, put a reverse proxy with HTTPS in " +
      "front (see docs/OPERATIONS.md) and set DEFENDSEC_COOKIE_SECURE=true and " +
      "DEFENDSEC_PUBLIC_CONSOLE_URL=https://your-host.",
  );
}

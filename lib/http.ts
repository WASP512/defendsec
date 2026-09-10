import { NextResponse } from "next/server";

// A relative Location keeps redirects pointing at whatever host the browser
// used. `request.url` reports the bind address, which is 0.0.0.0 for the
// standalone server, and sending that to the browser breaks the redirect.
export function redirectTo(path: string) {
  return new NextResponse(null, {
    status: 303,
    headers: { Location: path },
  });
}

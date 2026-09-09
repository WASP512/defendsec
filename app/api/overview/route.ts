import { NextResponse } from "next/server";
import { ensureStore } from "@/lib/store";
import { isOnline } from "@/lib/policies";
import { publicDevice } from "@/lib/store";

export const runtime = "nodejs";

export async function GET() {
  const store = await ensureStore();
  const devices = store.devices.map(publicDevice);
  const online = store.devices.filter((d) => isOnline(d)).length;
  return NextResponse.json({
    enrollSecret: store.enrollSecret,
    total: store.devices.length,
    online,
    offline: store.devices.length - online,
    samples: store.devices.filter((d) => d.sample).length,
    live: store.devices.filter((d) => !d.sample).length,
    platforms: {
      darwin: store.devices.filter((d) => d.platform === "darwin").length,
      windows: store.devices.filter((d) => d.platform === "windows").length,
      linux: store.devices.filter((d) => d.platform === "linux").length,
    },
    devices,
  });
}

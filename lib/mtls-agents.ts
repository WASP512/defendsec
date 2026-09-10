import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Device, Platform } from "./types";

type MtlsFile = {
  devices?: {
    id: string;
    hostname: string;
    platform?: string;
    osName?: string;
    osVersion?: string;
    arch?: string;
    uptimeSeconds?: number;
    lastSeen: string;
    connected?: boolean;
    certFingerprint?: string;
  }[];
};

function asPlatform(value: string | undefined): Platform {
  if (value === "darwin" || value === "windows" || value === "linux") return value;
  return "unknown";
}

export async function loadMtlsDevices(): Promise<Device[]> {
  try {
    const raw = await readFile(join(process.cwd(), "data", "mtls-agents.json"), "utf8");
    const parsed = JSON.parse(raw) as MtlsFile;
    return (parsed.devices ?? []).map((item) => ({
      id: item.id,
      hostname: item.hostname,
      platform: asPlatform(item.platform),
      osName: item.osName ?? "Unknown",
      osVersion: item.osVersion ?? "",
      arch: item.arch ?? "",
      serial: item.certFingerprint?.slice(0, 16) ?? "",
      hardwareModel: "mTLS gRPC agent",
      cpu: "",
      memoryMb: 0,
      diskEncryption: null,
      firewall: null,
      ipAddresses: [],
      username: "",
      uptimeSeconds: item.uptimeSeconds ?? 0,
      software: [],
      pendingUpdates: [],
      patchInventory: null,
      fim: [],
      fimBaseline: [],
      sample: false,
      enrolledAt: item.lastSeen,
      lastSeen: item.lastSeen,
      nodeKey: "",
    }));
  } catch {
    return [];
  }
}

export function mergeDevices(fromStore: Device[], mtls: Device[]) {
  const ids = new Set(fromStore.map((d) => d.id));
  const hostnames = new Set(fromStore.filter((d) => !d.sample).map((d) => d.hostname.toLowerCase()));
  const extra = mtls.filter((d) => !ids.has(d.id) && !hostnames.has(d.hostname.toLowerCase()));
  const merged = fromStore.map((device) => {
    const live = mtls.find(
      (item) => item.id === device.id || item.hostname.toLowerCase() === device.hostname.toLowerCase(),
    );
    if (!live) return device;
    return { ...device, lastSeen: live.lastSeen, hardwareModel: device.hardwareModel || live.hardwareModel };
  });
  return [...merged, ...extra];
}

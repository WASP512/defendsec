import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Device, FimEvent, FimFile, PatchInventory, Platform, SoftwareItem, PendingUpdate } from "./types";

type MtlsFile = {
  fimEvents?: FimEvent[];
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
    isolated?: boolean;
    serial?: string;
    hardwareModel?: string;
    cpu?: string;
    memoryMb?: number;
    diskEncryption?: boolean | null;
    firewall?: boolean | null;
    ipAddresses?: string[];
    username?: string;
    software?: SoftwareItem[];
    pendingUpdates?: PendingUpdate[];
    patchInventory?: PatchInventory | null;
    fim?: FimFile[];
    fimBaseline?: FimFile[];
  }[];
};

function asPlatform(value: string | undefined): Platform {
  if (value === "darwin" || value === "windows" || value === "linux") return value;
  return "unknown";
}

export async function loadMtlsFile(): Promise<MtlsFile> {
  try {
    const raw = await readFile(join(process.cwd(), "data", "defendsec-agents.json"), "utf8");
    return JSON.parse(raw) as MtlsFile;
  } catch {
    return {};
  }
}

export async function loadMtlsDevices(): Promise<Device[]> {
  const parsed = await loadMtlsFile();
  return (parsed.devices ?? []).map((item) => ({
    id: item.id,
    hostname: item.hostname,
    platform: asPlatform(item.platform),
    osName: item.osName ?? "Unknown",
    osVersion: item.osVersion ?? "",
    arch: item.arch ?? "",
    serial: item.serial ?? item.certFingerprint?.slice(0, 16) ?? "",
    hardwareModel: item.hardwareModel || "mTLS gRPC agent",
    cpu: item.cpu ?? "",
    memoryMb: item.memoryMb ?? 0,
    diskEncryption: item.diskEncryption ?? null,
    firewall: item.firewall ?? null,
    ipAddresses: item.ipAddresses ?? [],
    username: item.username ?? "",
    uptimeSeconds: item.uptimeSeconds ?? 0,
    software: item.software ?? [],
    pendingUpdates: item.pendingUpdates ?? [],
    patchInventory: item.patchInventory ?? null,
    fim: item.fim ?? [],
    fimBaseline: item.fimBaseline ?? [],
    sample: false,
    enrolledAt: item.lastSeen,
    lastSeen: item.lastSeen,
    nodeKey: "",
    isolated: Boolean(item.isolated),
    mtlsDeviceId: item.id,
  }));
}

export async function loadMtlsFimEvents(): Promise<FimEvent[]> {
  const parsed = await loadMtlsFile();
  return (parsed.fimEvents ?? []).map((event) => ({ ...event, sample: false }));
}

export function mergeDevices(fromStore: Device[], mtls: Device[]) {
  const ids = new Set(fromStore.map((d) => d.id));
  const hostnames = new Set(fromStore.filter((d) => !d.sample).map((d) => d.hostname.toLowerCase()));
  const extra = mtls.filter((d) => !ids.has(d.id) && !hostnames.has(d.hostname.toLowerCase()));
  const merged = fromStore.map((device) => {
    const live = mtls.find(
      (item) => item.id === device.id || item.hostname.toLowerCase() === device.hostname.toLowerCase(),
    );
    if (!live) return { ...device, isolated: device.isolated ?? false, mtlsDeviceId: device.mtlsDeviceId ?? "" };
    const useInv = live.software.length > 0 || live.fim.length > 0 || live.patchInventory != null;
    return {
      ...device,
      lastSeen: live.lastSeen,
      isolated: live.isolated,
      mtlsDeviceId: live.id,
      osName: useInv ? live.osName || device.osName : device.osName,
      osVersion: useInv ? live.osVersion || device.osVersion : device.osVersion,
      arch: useInv ? live.arch || device.arch : device.arch,
      serial: useInv ? live.serial || device.serial : device.serial,
      hardwareModel: live.hardwareModel || device.hardwareModel,
      cpu: useInv ? live.cpu || device.cpu : device.cpu,
      memoryMb: useInv && live.memoryMb ? live.memoryMb : device.memoryMb,
      diskEncryption: useInv ? live.diskEncryption : device.diskEncryption,
      firewall: useInv ? live.firewall : device.firewall,
      ipAddresses: useInv && live.ipAddresses.length ? live.ipAddresses : device.ipAddresses,
      username: useInv ? live.username || device.username : device.username,
      uptimeSeconds: live.uptimeSeconds || device.uptimeSeconds,
      software: useInv ? live.software : device.software,
      pendingUpdates: useInv ? live.pendingUpdates : device.pendingUpdates,
      patchInventory: useInv ? live.patchInventory : device.patchInventory,
      fim: useInv ? live.fim : device.fim,
      fimBaseline: useInv ? live.fimBaseline : device.fimBaseline,
    };
  });
  return [...merged, ...extra];
}

export async function loadFleet(fromStore: Device[]) {
  return mergeDevices(fromStore, await loadMtlsDevices());
}

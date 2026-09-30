import { readFile, stat } from "node:fs/promises";
import { dataPath } from "./data-paths";
import type { Device, FimEvent, FimFile, PatchInventory, Platform, SoftwareItem, PendingUpdate } from "./types";

type MtlsFile = {
  fimEvents?: FimEvent[];
  devices?: {
    id: string;
    hostname: string;
    agentVersion?: string;
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

// The export is rewritten at most every 30 seconds and is tens of megabytes
// at fleet scale, so it is parsed once per version rather than once per
// request (roadmap 5.5). The version is its mtime and size.
//
// When a new version appears and one is already loaded, the loaded one is
// served while the new one is parsed in the background (stale while
// revalidate). The export itself trails the control plane by up to 30
// seconds, so serving the previous version for a moment more costs little,
// while making the next visitor wait for a multi-second parse is exactly
// the delay this exists to remove.
let fileCache: { key: string; data: MtlsFile } | null = null;
let refreshing: Promise<void> | null = null;

async function parseExport(path: string, key: string): Promise<MtlsFile> {
  const data = JSON.parse(await readFile(path, "utf8")) as MtlsFile;
  fileCache = { key, data };
  return data;
}

export async function loadMtlsFile(): Promise<MtlsFile> {
  const path = dataPath("defendsec-agents.json");
  try {
    const st = await stat(path);
    const key = `${st.mtimeMs}:${st.size}`;
    if (fileCache?.key === key) return fileCache.data;
    if (fileCache) {
      refreshing ??= parseExport(path, key)
        .then(() => undefined)
        .catch(() => undefined)
        .finally(() => {
          refreshing = null;
        });
      return fileCache.data;
    }
    return await parseExport(path, key);
  } catch {
    return fileCache?.data ?? {};
  }
}

// fleetVersion identifies the export last loaded, for caching work derived
// from it. Empty before the first load.
export function fleetVersion(): string {
  return fileCache?.key ?? "";
}

let devicesCache: { key: string; devices: Device[] } | null = null;

export async function loadMtlsDevices(): Promise<Device[]> {
  const parsed = await loadMtlsFile();
  if (devicesCache && devicesCache.key === fleetVersion() && fleetVersion() !== "") return devicesCache.devices;
  const devices = mapMtlsDevices(parsed);
  devicesCache = { key: fleetVersion(), devices };
  return devices;
}

function mapMtlsDevices(parsed: MtlsFile): Device[] {
  return (parsed.devices ?? []).map((item) => ({
    id: item.id,
    hostname: item.hostname,
    agentVersion: item.agentVersion ?? "",
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
      agentVersion: live.agentVersion || device.agentVersion,
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

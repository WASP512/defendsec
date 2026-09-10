import { copyFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { sampleFimEvents, sampleFleet } from "./demo";
import type { CheckinPayload, Device, FimEvent, FimFile, StoreData } from "./types";
import { STORE_SCHEMA_VERSION } from "./types";

export class StoreCorruptError extends Error {
  constructor(message = "Host database is corrupt and was not overwritten") {
    super(message);
    this.name = "StoreCorruptError";
  }
}

const DATA_PATH = join(process.cwd(), "data", "keel.json");
const BACKUP_PATH = join(process.cwd(), "data", "keel.json.bak");

let queue: Promise<void> = Promise.resolve();

function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
  const next = queue.then(fn, fn);
  queue = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
}

function copyFim(files: FimFile[]): FimFile[] {
  return files.map((file) => ({ ...file }));
}

function emptyStore(): StoreData {
  return {
    schemaVersion: STORE_SCHEMA_VERSION,
    enrollSecret: randomBytes(12).toString("hex"),
    devices: [],
    fimEvents: [],
    triages: [],
  };
}

function normalizeDevice(device: Device): Device {
  const fim = device.fim ?? [];
  return {
    ...device,
    software: device.software ?? [],
    pendingUpdates: device.pendingUpdates ?? [],
    patchInventory: device.patchInventory ?? null,
    fim,
    fimBaseline: device.fimBaseline ?? copyFim(fim),
    isolated: device.isolated ?? false,
    mtlsDeviceId: device.mtlsDeviceId ?? "",
  };
}

function normalizeStore(data: StoreData): StoreData {
  return {
    schemaVersion: data.schemaVersion ?? 1,
    enrollSecret: data.enrollSecret || randomBytes(12).toString("hex"),
    devices: (data.devices ?? []).map(normalizeDevice),
    fimEvents: data.fimEvents ?? [],
    triages: data.triages ?? [],
  };
}

async function readStore(): Promise<StoreData | null> {
  let raw: string;
  try {
    raw = await readFile(DATA_PATH, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    throw new StoreCorruptError(
      `Could not read ${DATA_PATH}: ${error instanceof Error ? error.message : "unknown error"}`,
    );
  }
  if (!raw.trim()) {
    throw new StoreCorruptError(`${DATA_PATH} is empty. Restore data/keel.json.bak if you have one.`);
  }
  try {
    const parsed = JSON.parse(raw) as StoreData;
    if (!Array.isArray(parsed.devices)) {
      throw new Error("devices is not an array");
    }
    return normalizeStore(parsed);
  } catch (error) {
    throw new StoreCorruptError(
      `${DATA_PATH} is not valid Keel data (${error instanceof Error ? error.message : "parse error"}). Restore data/keel.json.bak; the server will not overwrite this file.`,
    );
  }
}

async function writeStore(data: StoreData) {
  await mkdir(dirname(DATA_PATH), { recursive: true });
  const tmp = `${DATA_PATH}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
  await rename(tmp, DATA_PATH);
  try {
    await copyFile(DATA_PATH, BACKUP_PATH);
  } catch {
    // Primary is already durable; backup is best-effort.
  }
}

export function publicDevice(device: Device) {
  return {
    id: device.id,
    hostname: device.hostname,
    platform: device.platform,
    osName: device.osName,
    osVersion: device.osVersion,
    arch: device.arch,
    serial: device.serial,
    hardwareModel: device.hardwareModel,
    cpu: device.cpu,
    memoryMb: device.memoryMb,
    diskEncryption: device.diskEncryption,
    firewall: device.firewall,
    ipAddresses: device.ipAddresses,
    username: device.username,
    uptimeSeconds: device.uptimeSeconds,
    software: device.software,
    pendingUpdates: device.pendingUpdates,
    patchInventory: device.patchInventory,
    fim: device.fim,
    fimBaseline: device.fimBaseline,
    sample: device.sample,
    enrolledAt: device.enrolledAt,
    lastSeen: device.lastSeen,
    isolated: device.isolated ?? false,
    mtlsDeviceId: device.mtlsDeviceId ?? "",
  };
}

export async function rotateEnrollSecret() {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) throw new StoreCorruptError("Host database is missing");
    data.enrollSecret = randomBytes(12).toString("hex");
    await writeStore(data);
    return data.enrollSecret;
  });
}

export async function enrollDevice(secret: string, hostname: string) {
  return runExclusive(async () => {
    const existingFile = await readStore();
    const data = existingFile ?? emptyStore();
    if (secret !== data.enrollSecret) {
      return { ok: false as const, error: "Invalid enroll secret" };
    }
    const existing = data.devices.find(
      (d) => d.hostname.toLowerCase() === hostname.toLowerCase() && !d.sample,
    );
    if (existing) {
      existing.lastSeen = new Date().toISOString();
      await writeStore(data);
      return {
        ok: true as const,
        nodeKey: existing.nodeKey,
        deviceId: existing.id,
        existing: true as const,
      };
    }
    const device: Device = {
      id: randomBytes(8).toString("hex"),
      hostname,
      platform: "unknown",
      osName: "Unknown",
      osVersion: "",
      arch: "",
      serial: "",
      hardwareModel: "",
      cpu: "",
      memoryMb: 0,
      diskEncryption: null,
      firewall: null,
      ipAddresses: [],
      username: "",
      uptimeSeconds: 0,
      software: [],
      pendingUpdates: [],
      patchInventory: null,
      fim: [],
      fimBaseline: [],
      sample: false,
      enrolledAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      nodeKey: randomBytes(24).toString("hex"),
    };
    data.devices.push(device);
    await writeStore(data);
    return {
      ok: true as const,
      nodeKey: device.nodeKey,
      deviceId: device.id,
      existing: false as const,
    };
  });
}

function applyFim(data: StoreData, device: Device, incoming: NonNullable<CheckinPayload["fim"]>) {
  if (device.fimBaseline.length === 0 && incoming.length > 0) {
    device.fimBaseline = copyFim(incoming);
  }
  const previous = new Map(device.fim.map((file) => [file.path, file.sha256]));
  const events: FimEvent[] = [];
  for (const file of incoming) {
    const last = previous.get(file.path);
    if (last && last !== file.sha256) {
      events.push({
        id: randomBytes(6).toString("hex"),
        deviceId: device.id,
        hostname: device.hostname,
        path: file.path,
        previous: last,
        current: file.sha256,
        detectedAt: new Date().toISOString(),
        sample: false,
      });
    }
  }
  device.fim = incoming;
  data.fimEvents = [...events, ...data.fimEvents].slice(0, 200);
}

export async function checkin(payload: CheckinPayload) {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) {
      return { ok: false as const, error: "Unknown node key" };
    }
    const device = data.devices.find((d) => d.nodeKey === payload.nodeKey);
    if (!device) {
      return { ok: false as const, error: "Unknown node key" };
    }
    device.hostname = payload.hostname || device.hostname;
    device.platform = payload.platform || device.platform;
    device.osName = payload.osName || device.osName;
    device.osVersion = payload.osVersion || device.osVersion;
    device.arch = payload.arch || device.arch;
    device.serial = payload.serial ?? device.serial;
    device.hardwareModel = payload.hardwareModel ?? device.hardwareModel;
    device.cpu = payload.cpu ?? device.cpu;
    device.memoryMb = payload.memoryMb ?? device.memoryMb;
    device.diskEncryption =
      payload.diskEncryption === undefined
        ? device.diskEncryption
        : payload.diskEncryption;
    device.firewall =
      payload.firewall === undefined ? device.firewall : payload.firewall;
    device.ipAddresses = payload.ipAddresses ?? device.ipAddresses;
    device.username = payload.username ?? device.username;
    device.uptimeSeconds = payload.uptimeSeconds ?? device.uptimeSeconds;
    device.software = payload.software ?? device.software;
    device.pendingUpdates = payload.pendingUpdates ?? device.pendingUpdates;
    if (payload.patchInventory !== undefined) {
      device.patchInventory = payload.patchInventory;
    }
    if (payload.fim) {
      applyFim(data, device, payload.fim);
    }
    device.lastSeen = new Date().toISOString();
    await writeStore(data);
    return { ok: true as const, deviceId: device.id };
  });
}

export async function replaceSampleFleet(devices: Device[]) {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) throw new StoreCorruptError("Host database is missing");
    const live = data.devices.filter((d) => !d.sample);
    data.devices = [...live, ...devices];
    data.fimEvents = [
      ...data.fimEvents.filter((event) => !event.sample),
      ...sampleFimEvents(devices),
    ];
    data.schemaVersion = STORE_SCHEMA_VERSION;
    await writeStore(data);
    return data;
  });
}

export async function clearSampleFleet() {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) throw new StoreCorruptError("Host database is missing");
    data.devices = data.devices.filter((d) => !d.sample);
    data.fimEvents = data.fimEvents.filter((event) => !event.sample);
    await writeStore(data);
    return data;
  });
}

export async function setTriage(key: string, status: "open" | "acknowledged") {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) throw new StoreCorruptError("Host database is missing");
    const rest = data.triages.filter((item) => item.key !== key);
    data.triages = [...rest, { key, status, updatedAt: new Date().toISOString() }];
    await writeStore(data);
    return data.triages;
  });
}

export async function acceptFimBaseline(deviceId: string) {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) throw new StoreCorruptError("Host database is missing");
    const device = data.devices.find((item) => item.id === deviceId);
    if (!device) return { ok: false as const, error: "Device not found" };
    device.fimBaseline = copyFim(device.fim);
    await writeStore(data);
    return { ok: true as const, device };
  });
}

export async function ensureStore() {
  return runExclusive(async () => {
    const data = await readStore();
    if (!data) {
      const created = emptyStore();
      created.devices = sampleFleet();
      created.fimEvents = sampleFimEvents(created.devices);
      await writeStore(created);
      return created;
    }
    const samples = data.devices.filter((d) => d.sample);
    const staleSamples =
      samples.length > 0 &&
      samples.every((d) => d.pendingUpdates.length === 0 && d.fim.length === 0);
    const needsSchema = (data.schemaVersion ?? 1) < STORE_SCHEMA_VERSION;
    if (data.devices.length === 0 || staleSamples || needsSchema) {
      const live = data.devices.filter((d) => !d.sample);
      data.devices = [...live, ...sampleFleet()];
      data.fimEvents = [
        ...data.fimEvents.filter((event) => !event.sample),
        ...sampleFimEvents(data.devices.filter((d) => d.sample)),
      ];
      data.schemaVersion = STORE_SCHEMA_VERSION;
      await writeStore(data);
    }
    return data;
  });
}

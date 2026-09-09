import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { sampleFleet } from "./demo";
import type { CheckinPayload, Device, StoreData } from "./types";

const DATA_PATH = join(process.cwd(), "data", "keel.json");

let queue: Promise<void> = Promise.resolve();

function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
  const next = queue.then(fn, fn);
  queue = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
}

function emptyStore(): StoreData {
  return {
    enrollSecret: randomBytes(12).toString("hex"),
    devices: [],
  };
}

async function readStore(): Promise<StoreData> {
  try {
    const raw = await readFile(DATA_PATH, "utf8");
    const parsed = JSON.parse(raw) as StoreData;
    if (!parsed.enrollSecret || !Array.isArray(parsed.devices)) {
      return emptyStore();
    }
    return parsed;
  } catch {
    return emptyStore();
  }
}

async function writeStore(data: StoreData) {
  await mkdir(dirname(DATA_PATH), { recursive: true });
  const tmp = `${DATA_PATH}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
  await rename(tmp, DATA_PATH);
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
    sample: device.sample,
    enrolledAt: device.enrolledAt,
    lastSeen: device.lastSeen,
  };
}

export async function getStore() {
  return runExclusive(readStore);
}

export async function rotateEnrollSecret() {
  return runExclusive(async () => {
    const data = await readStore();
    data.enrollSecret = randomBytes(12).toString("hex");
    await writeStore(data);
    return data.enrollSecret;
  });
}

export async function enrollDevice(secret: string, hostname: string) {
  return runExclusive(async () => {
    const data = await readStore();
    if (secret !== data.enrollSecret) {
      return { ok: false as const, error: "Invalid enroll secret" };
    }
    const existing = data.devices.find(
      (d) => d.hostname.toLowerCase() === hostname.toLowerCase() && !d.sample,
    );
    if (existing) {
      existing.nodeKey = randomBytes(24).toString("hex");
      existing.lastSeen = new Date().toISOString();
      await writeStore(data);
      return { ok: true as const, nodeKey: existing.nodeKey, deviceId: existing.id };
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
      sample: false,
      enrolledAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      nodeKey: randomBytes(24).toString("hex"),
    };
    data.devices.push(device);
    await writeStore(data);
    return { ok: true as const, nodeKey: device.nodeKey, deviceId: device.id };
  });
}

export async function checkin(payload: CheckinPayload) {
  return runExclusive(async () => {
    const data = await readStore();
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
    device.lastSeen = new Date().toISOString();
    await writeStore(data);
    return { ok: true as const, deviceId: device.id };
  });
}

export async function replaceSampleFleet(devices: Device[]) {
  return runExclusive(async () => {
    const data = await readStore();
    const live = data.devices.filter((d) => !d.sample);
    data.devices = [...live, ...devices];
    await writeStore(data);
    return data;
  });
}

export async function clearSampleFleet() {
  return runExclusive(async () => {
    const data = await readStore();
    data.devices = data.devices.filter((d) => !d.sample);
    await writeStore(data);
    return data;
  });
}

export async function ensureStore() {
  return runExclusive(async () => {
    const data = await readStore();
    if (data.devices.length === 0) {
      data.devices = sampleFleet();
    }
    await writeStore(data);
    return data;
  });
}

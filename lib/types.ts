export type Platform = "darwin" | "windows" | "linux" | "unknown";

export type SoftwareItem = {
  name: string;
  version: string;
};

export type PendingUpdate = {
  name: string;
  current: string;
  available: string;
};

export type FimFile = {
  path: string;
  sha256: string;
  size: number;
  mtime: string | null;
};

export type FimEvent = {
  id: string;
  deviceId: string;
  hostname: string;
  path: string;
  previous: string;
  current: string;
  detectedAt: string;
  sample: boolean;
};

export type Severity = "critical" | "high" | "medium" | "low";

export type Advisory = {
  id: string;
  cve: string;
  package: string;
  below: string;
  severity: Severity;
  summary: string;
};

export type FindingStatus = "open" | "acknowledged";

export type FindingTriage = {
  key: string;
  status: FindingStatus;
  updatedAt: string;
};

export type Finding = {
  key: string;
  advisory: Advisory;
  packageName: string;
  version: string;
  deviceId: string;
  hostname: string;
  status: FindingStatus;
};

export type PatchInventory = "ok" | "unsupported" | "error";

export type Device = {
  id: string;
  hostname: string;
  platform: Platform;
  osName: string;
  osVersion: string;
  arch: string;
  serial: string;
  hardwareModel: string;
  cpu: string;
  memoryMb: number;
  diskEncryption: boolean | null;
  firewall: boolean | null;
  ipAddresses: string[];
  username: string;
  uptimeSeconds: number;
  software: SoftwareItem[];
  pendingUpdates: PendingUpdate[];
  patchInventory: PatchInventory | null;
  fim: FimFile[];
  fimBaseline: FimFile[];
  sample: boolean;
  enrolledAt: string;
  lastSeen: string;
  nodeKey: string;
  isolated?: boolean;
  mtlsDeviceId?: string;
};

export type CheckinPayload = {
  nodeKey: string;
  hostname: string;
  platform: Platform;
  osName: string;
  osVersion: string;
  arch: string;
  serial?: string;
  hardwareModel?: string;
  cpu?: string;
  memoryMb?: number;
  diskEncryption?: boolean | null;
  firewall?: boolean | null;
  ipAddresses?: string[];
  username?: string;
  uptimeSeconds?: number;
  software?: SoftwareItem[];
  pendingUpdates?: PendingUpdate[];
  patchInventory?: PatchInventory | null;
  fim?: FimFile[];
};

export type PolicyStatus = "pass" | "fail" | "unknown";

export type PolicyResult = {
  id: string;
  name: string;
  description: string;
  status: PolicyStatus;
  detail: string;
};

export type PublicDevice = Omit<Device, "nodeKey">;

export type StoreData = {
  schemaVersion: number;
  enrollSecret: string;
  devices: Device[];
  fimEvents: FimEvent[];
  triages: FindingTriage[];
};

export const STORE_SCHEMA_VERSION = 2;

export const ONLINE_WINDOW_MS = 2 * 60 * 1000;

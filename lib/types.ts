export type Platform = "darwin" | "windows" | "linux" | "unknown";

export type SoftwareItem = {
  name: string;
  version: string;
};

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
  sample: boolean;
  enrolledAt: string;
  lastSeen: string;
  nodeKey: string;
};

export type EnrollPayload = {
  enrollSecret: string;
  hostname?: string;
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
  enrollSecret: string;
  devices: Device[];
};

export const ONLINE_WINDOW_MS = 2 * 60 * 1000;

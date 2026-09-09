import type { Device, PolicyResult, PolicyStatus } from "./types";
import { ONLINE_WINDOW_MS } from "./types";

export function isOnline(device: Device, now = Date.now()) {
  return now - new Date(device.lastSeen).getTime() < ONLINE_WINDOW_MS;
}

function statusFrom(ok: boolean | null): PolicyStatus {
  if (ok === null) return "unknown";
  return ok ? "pass" : "fail";
}

export const POLICY_DEFS = [
  {
    id: "online",
    name: "Agent checking in",
    description: "Host reported inventory within the last two minutes.",
  },
  {
    id: "disk-encryption",
    name: "Disk encryption",
    description: "FileVault, BitLocker, or LUKS reported as enabled.",
  },
  {
    id: "firewall",
    name: "Host firewall",
    description: "Built-in OS firewall reported as enabled.",
  },
  {
    id: "supported-os",
    name: "Supported OS",
    description: "macOS 14+, Windows 11, or a current Ubuntu LTS.",
  },
] as const;

function supportedOs(device: Device): boolean | null {
  const version = device.osVersion.toLowerCase();
  if (device.platform === "darwin") {
    const major = Number.parseInt(version.split(".")[0] ?? "", 10);
    if (Number.isNaN(major)) return null;
    return major >= 14;
  }
  if (device.platform === "windows") {
    if (!version) return null;
    return version.includes("11") || version.includes("2022") || version.includes("2025");
  }
  if (device.platform === "linux") {
    if (!version) return null;
    const match = version.match(/(\d+)\.(\d+)/);
    if (!match) return version.includes("24.04") || version.includes("22.04");
    const major = Number(match[1]);
    const minor = Number(match[2]);
    return major > 22 || (major === 22 && minor >= 4);
  }
  return null;
}

export function evaluateDevice(device: Device): PolicyResult[] {
  const online = isOnline(device);
  return [
    {
      id: "online",
      name: "Agent checking in",
      description: POLICY_DEFS[0].description,
      status: statusFrom(online),
      detail: online
        ? `Last seen ${device.lastSeen}`
        : `Last seen ${device.lastSeen} — considered offline`,
    },
    {
      id: "disk-encryption",
      name: "Disk encryption",
      description: POLICY_DEFS[1].description,
      status: statusFrom(device.diskEncryption),
      detail:
        device.diskEncryption === null
          ? "Agent could not determine encryption state"
          : device.diskEncryption
            ? "Encryption reported on"
            : "Encryption reported off",
    },
    {
      id: "firewall",
      name: "Host firewall",
      description: POLICY_DEFS[2].description,
      status: statusFrom(device.firewall),
      detail:
        device.firewall === null
          ? "Agent could not determine firewall state"
          : device.firewall
            ? "Firewall reported on"
            : "Firewall reported off",
    },
    {
      id: "supported-os",
      name: "Supported OS",
      description: POLICY_DEFS[3].description,
      status: statusFrom(supportedOs(device)),
      detail: `${device.osName} ${device.osVersion}`.trim() || "Unknown OS",
    },
  ];
}

export function policySummary(devices: Device[]) {
  return POLICY_DEFS.map((def) => {
    const results = devices.map((d) => evaluateDevice(d).find((p) => p.id === def.id)!);
    return {
      ...def,
      passing: results.filter((r) => r.status === "pass").length,
      failing: results.filter((r) => r.status === "fail").length,
      unknown: results.filter((r) => r.status === "unknown").length,
    };
  });
}

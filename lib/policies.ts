import type { Device, FindingTriage, PolicyResult, PolicyStatus } from "./types";
import { ONLINE_WINDOW_MS } from "./types";
import { findingsForDevice } from "./advisories";
import { SAMPLE_KEEP_ONLINE } from "./demo";

export function isOnline(
  device: Pick<Device, "sample" | "hostname" | "lastSeen">,
  now = Date.now(),
) {
  if (device.sample && SAMPLE_KEEP_ONLINE.has(device.hostname)) return true;
  return now - new Date(device.lastSeen).getTime() < ONLINE_WINDOW_MS;
}

export function fimDriftPaths(device: Device) {
  const drifted: string[] = [];
  const baseline = new Map(device.fimBaseline.map((file) => [file.path, file.sha256]));
  const current = new Map(device.fim.map((file) => [file.path, file.sha256]));
  for (const [path, hash] of current) {
    const expected = baseline.get(path);
    if (expected && expected !== hash) drifted.push(path);
  }
  for (const path of baseline.keys()) {
    if (!current.has(path)) drifted.push(path);
  }
  return [...new Set(drifted)];
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
  {
    id: "vulns",
    name: "No high/critical advisories",
    description: "Installed software is not older than the local advisory floor.",
  },
  {
    id: "patches",
    name: "No pending patches",
    description: "Agent reported no outstanding OS or package updates.",
  },
  {
    id: "fim",
    name: "Watched files unchanged",
    description: "Current hashes match the last accepted baseline.",
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

function patchStatus(device: Device): PolicyResult {
  if (device.patchInventory !== "ok") {
    const detail =
      device.patchInventory === "unsupported"
        ? "This platform does not report a patch catalog yet"
        : device.patchInventory === "error"
          ? "Agent could not collect pending updates"
          : "No patch inventory reported yet";
    return {
      id: "patches",
      name: "No pending patches",
      description: POLICY_DEFS[5].description,
      status: "unknown",
      detail,
    };
  }
  return {
    id: "patches",
    name: "No pending patches",
    description: POLICY_DEFS[5].description,
    status: statusFrom(device.pendingUpdates.length === 0),
    detail:
      device.pendingUpdates.length === 0
        ? "No pending updates"
        : `${device.pendingUpdates.length} pending`,
  };
}

export function evaluateDevice(
  device: Device,
  _fimEvents: unknown[] = [],
  triages: FindingTriage[] = [],
): PolicyResult[] {
  void _fimEvents;
  const online = isOnline(device);
  const serious = findingsForDevice(device, triages).filter(
    (f) =>
      f.status === "open" &&
      (f.advisory.severity === "critical" || f.advisory.severity === "high"),
  );
  const drifted = fimDriftPaths(device);
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
    {
      id: "vulns",
      name: "No high/critical advisories",
      description: POLICY_DEFS[4].description,
      status: statusFrom(serious.length === 0),
      detail:
        serious.length === 0
          ? "No high or critical matches in the local catalog"
          : serious.map((f) => `${f.advisory.cve} (${f.packageName})`).join(", "),
    },
    patchStatus(device),
    {
      id: "fim",
      name: "Watched files unchanged",
      description: POLICY_DEFS[6].description,
      status:
        device.fim.length === 0 && device.fimBaseline.length === 0
          ? "unknown"
          : statusFrom(drifted.length === 0),
      detail:
        drifted.length > 0
          ? drifted.join(", ")
          : device.fim.length === 0
            ? "No integrity paths reported"
            : `${device.fim.length} paths match the accepted baseline`,
    },
  ];
}

export function policySummary(
  devices: Device[],
  _fimEvents: unknown[] = [],
  triages: FindingTriage[] = [],
) {
  void _fimEvents;
  return POLICY_DEFS.map((def) => {
    const results = devices.map(
      (d) => evaluateDevice(d, _fimEvents, triages).find((p) => p.id === def.id)!,
    );
    return {
      ...def,
      passing: results.filter((r) => r.status === "pass").length,
      failing: results.filter((r) => r.status === "fail").length,
      unknown: results.filter((r) => r.status === "unknown").length,
    };
  });
}

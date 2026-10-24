import { supportedOs, windowsSupportOf } from "./supported-os.ts";
import type { Device, FindingTriage, PolicyResult, PolicyStatus } from "./types";
import { ONLINE_WINDOW_MS } from "./types";
import { SAMPLE_KEEP_ONLINE } from "./demo";
import { coverageNotice, seriousOpen, type DeviceFindingsSummary } from "./findings-model.ts";

/**
 * What the control plane says about a host's findings. `available: false` means
 * it could not be asked, which is not the same as "no findings".
 */
export type VulnInput =
  | { available: false }
  | { available: true; summary: DeviceFindingsSummary | undefined };

/** The id apid knows a host by: the mTLS device id when there is one. */
export function apidId(device: Pick<Device, "id" | "mtlsDeviceId">): string {
  return device.mtlsDeviceId || device.id;
}

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
    description: "A vendor-supported release: Ubuntu 22.04+, Debian 12+, Fedora (current), RHEL 8+, openSUSE Leap 16+ / Tumbleweed, or a Windows edition and build that Microsoft still patches (from the endoflife.date calendar).",
  },
  {
    id: "vulns",
    name: "No high/critical advisories",
    description:
      "No finding with a fix available that is rated high or critical, or is on the CISA KEV list, matched against the distro's own advisories.",
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

function vulnPolicy(vulns: VulnInput, triages: FindingTriage[]): { status: PolicyStatus; detail: string } {
  if (!vulns.available) {
    return { status: "unknown", detail: "Findings unavailable: the control plane could not be reached" };
  }
  if (!vulns.summary) {
    return { status: "unknown", detail: "Not assessed yet: no match has run for this host" };
  }
  const notice = coverageNotice({
    deviceId: vulns.summary.deviceId,
    distro: vulns.summary.distro,
    release: vulns.summary.release,
    coverage: vulns.summary.coverage,
    packages: 0,
    distroMapped: 0,
    upstream: 0,
    undecidable: 0,
    notAffected: 0,
    snapshotId: null,
    matchedAt: vulns.summary.matchedAt,
  });
  if (notice) return { status: "unknown", detail: notice.title };
  const n = seriousOpen(vulns.summary, triages);
  return n === 0
    ? { status: "pass", detail: "No high, critical or KEV findings with a fix available" }
    : { status: "fail", detail: `${n} high, critical or KEV finding${n === 1 ? "" : "s"} with a fix available` };
}

function supportedOsDetail(device: Device): string {
  const os = `${device.osName} ${device.osVersion}`.trim() || "Unknown OS";
  if (device.platform !== "windows") return os;
  const why = windowsSupportOf(device).reason;
  return `${os}: ${why}`;
}

export function evaluateDevice(
  device: Device,
  _fimEvents: unknown[] = [],
  triages: FindingTriage[] = [],
  vulns: VulnInput = { available: false },
): PolicyResult[] {
  void _fimEvents;
  const online = isOnline(device);
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
      detail: supportedOsDetail(device),
    },
    {
      id: "vulns",
      name: "No high/critical advisories",
      description: POLICY_DEFS[4].description,
      ...vulnPolicy(vulns, triages),
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
  vulns: Map<string, DeviceFindingsSummary> | null = null,
) {
  // Each device is evaluated once. Evaluating it once per policy repeated the
  // advisory matching seven times per host, which at 10,000 hosts made this
  // page take twenty seconds (roadmap 5.5 load test).
  const counts = new Map<string, { passing: number; failing: number; unknown: number }>(
    POLICY_DEFS.map((def) => [def.id, { passing: 0, failing: 0, unknown: 0 }]),
  );
  for (const device of devices) {
    const input: VulnInput = vulns
      ? { available: true, summary: vulns.get(apidId(device)) }
      : { available: false };
    for (const result of evaluateDevice(device, _fimEvents, triages, input)) {
      const c = counts.get(result.id);
      if (!c) continue;
      if (result.status === "pass") c.passing++;
      else if (result.status === "fail") c.failing++;
      else c.unknown++;
    }
  }
  return POLICY_DEFS.map((def) => ({ ...def, ...counts.get(def.id)! }));
}

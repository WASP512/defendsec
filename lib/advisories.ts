import type { Advisory, Device, Finding, FindingTriage, SoftwareItem } from "./types";

const PACKAGE_ALIASES: Record<string, string> = {
  "docker.io": "docker",
  "docker-ce": "docker",
  "docker-ee": "docker",
  "google-chrome": "google chrome",
  "google-chrome-stable": "google chrome",
  "google chrome": "google chrome",
  "adobe-photoshop": "adobe photoshop",
  "openssh": "openssh-server",
};

export function stripDebianEpoch(raw: string) {
  return raw.trim().replace(/^\d+:/, "");
}

function parseVersion(raw: string) {
  return stripDebianEpoch(raw)
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map((part) => Number.parseInt(part, 10));
}

/** Return true if installed is strictly older than the patched floor. */
export function versionOlderThan(installed: string, floor: string) {
  const a = parseVersion(installed);
  const b = parseVersion(floor);
  if (a.length === 0 || b.length === 0) return false;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const left = a[i] ?? 0;
    const right = b[i] ?? 0;
    if (left < right) return true;
    if (left > right) return false;
  }
  return false;
}

export function canonicalPackage(name: string) {
  const lower = name.toLowerCase().trim();
  if (PACKAGE_ALIASES[lower]) return PACKAGE_ALIASES[lower];
  const dashed = lower.replace(/_/g, "-");
  if (PACKAGE_ALIASES[dashed]) return PACKAGE_ALIASES[dashed];
  const spaced = dashed.replace(/-/g, " ");
  if (PACKAGE_ALIASES[spaced]) return PACKAGE_ALIASES[spaced];
  return spaced;
}

export function packageMatches(advisoryPackage: string, installedName: string) {
  return canonicalPackage(installedName) === canonicalPackage(advisoryPackage);
}

export const ADVISORIES: Advisory[] = [
  {
    id: "DEFENDSEC-CHROME-131",
    cve: "CVE-2024-4947",
    package: "google chrome",
    below: "132.0",
    severity: "high",
    summary: "Chrome before 132: type confusion in V8. Update to the current stable channel.",
  },
  {
    id: "DEFENDSEC-DOCKER-27",
    cve: "CVE-2024-41110",
    package: "docker",
    below: "26.1.4",
    severity: "critical",
    summary: "Authz plugin bypass in some Docker Engine builds. Upgrade the engine package.",
  },
  {
    id: "DEFENDSEC-GIT-234",
    cve: "CVE-2024-32002",
    package: "git",
    below: "2.45.1",
    severity: "high",
    summary: "Recursive clone can execute hooks from untrusted repos. Update Git.",
  },
  {
    id: "DEFENDSEC-OPENSSL",
    cve: "CVE-2024-5535",
    package: "openssl",
    below: "3.0.14",
    severity: "medium",
    summary: "SSL_select_next_proto use-after-free in older OpenSSL 3.0 builds.",
  },
  {
    id: "DEFENDSEC-OPENSSH",
    cve: "CVE-2024-6387",
    package: "openssh-server",
    below: "9.8p1",
    severity: "high",
    summary: "regreSSHion: signal handler race in sshd. Patch OpenSSH.",
  },
  {
    id: "DEFENDSEC-SLACK",
    cve: "CVE-2024-32300",
    package: "slack",
    below: "4.42.0",
    severity: "medium",
    summary: "Desktop client below 4.42 ships an outdated Electron. Update Slack.",
  },
  {
    id: "DEFENDSEC-PHOTOSHOP",
    cve: "CVE-2024-20767",
    package: "adobe photoshop",
    below: "25.9.1",
    severity: "high",
    summary: "Memory corruption in older Photoshop builds. Update Creative Cloud.",
  },
];

export function findingKey(deviceId: string, advisoryId: string, packageName: string) {
  return `${deviceId}:${advisoryId}:${packageName.toLowerCase()}`;
}

// Advisories indexed by canonical package name, built once per catalog.
// Matching used to compare every installed package with every advisory,
// normalising both names each time; at 10,000 hosts that was seconds of
// blocking CPU per page view (roadmap 5.5). The result is identical: an
// advisory applies exactly when the canonical names are equal.
const catalogIndex = new WeakMap<Advisory[], Map<string, Advisory[]>>();

function indexFor(advisories: Advisory[]): Map<string, Advisory[]> {
  let idx = catalogIndex.get(advisories);
  if (!idx) {
    idx = new Map();
    for (const advisory of advisories) {
      const key = canonicalPackage(advisory.package);
      const list = idx.get(key);
      if (list) list.push(advisory);
      else idx.set(key, [advisory]);
    }
    catalogIndex.set(advisories, idx);
  }
  return idx;
}

function matchSoftware(
  software: SoftwareItem[],
  device: Pick<Device, "id" | "hostname">,
  statusByKey: Map<string, FindingTriage["status"]>,
  idx: Map<string, Advisory[]>,
  findings: Finding[],
) {
  for (const item of software) {
    if (!item.version) continue;
    const candidates = idx.get(canonicalPackage(item.name));
    if (!candidates) continue;
    for (const advisory of candidates) {
      if (!versionOlderThan(item.version, advisory.below)) continue;
      const key = findingKey(device.id, advisory.id, item.name);
      findings.push({
        key,
        advisory,
        packageName: item.name,
        version: item.version,
        deviceId: device.id,
        hostname: device.hostname,
        status: statusByKey.get(key) ?? "open",
      });
    }
  }
}

export function findingsForSoftware(
  software: SoftwareItem[],
  device: Pick<Device, "id" | "hostname">,
  triages: FindingTriage[] = [],
  advisories: Advisory[] = ADVISORIES,
): Finding[] {
  const findings: Finding[] = [];
  matchSoftware(software, device, new Map(triages.map((t) => [t.key, t.status])), indexFor(advisories), findings);
  return findings;
}

export function findingsForDevice(
  device: Device,
  triages: FindingTriage[] = [],
  advisories: Advisory[] = ADVISORIES,
) {
  return findingsForSoftware(device.software, device, triages, advisories);
}

export function allFindings(
  devices: Device[],
  triages: FindingTriage[] = [],
  advisories: Advisory[] = ADVISORIES,
) {
  // One triage map and one index for the whole fleet, not one per host.
  const statusByKey = new Map(triages.map((t) => [t.key, t.status]));
  const idx = indexFor(advisories);
  const findings: Finding[] = [];
  for (const device of devices) matchSoftware(device.software, device, statusByKey, idx, findings);
  return findings;
}


export function findingsForDeviceWithCatalog(
  device: Device,
  triages: FindingTriage[] = [],
  advisories: Advisory[] = ADVISORIES,
) {
  return findingsForSoftware(device.software, device, triages, advisories);
}

export function severityRank(severity: Advisory["severity"]) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity];
}

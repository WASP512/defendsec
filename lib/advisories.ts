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

export function findingsForSoftware(
  software: SoftwareItem[],
  device: Pick<Device, "id" | "hostname">,
  triages: FindingTriage[] = [],
): Finding[] {
  const statusByKey = new Map(triages.map((item) => [item.key, item.status]));
  const findings: Finding[] = [];
  for (const item of software) {
    if (!item.version) continue;
    for (const advisory of ADVISORIES) {
      if (!packageMatches(advisory.package, item.name)) continue;
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
  return findings;
}

export function findingsForDevice(device: Device, triages: FindingTriage[] = []) {
  return findingsForSoftware(device.software, device, triages);
}

export function allFindings(devices: Device[], triages: FindingTriage[] = []) {
  return devices.flatMap((device) => findingsForDevice(device, triages));
}

export function severityRank(severity: Advisory["severity"]) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity];
}

import { randomBytes } from "node:crypto";
import type { Device } from "./types";

export const SAMPLE_KEEP_ONLINE = new Set([
  "ops-macbook-14",
  "finance-win-07",
  "build-linux-03",
]);

function ago(minutes: number) {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

function device(partial: Omit<Device, "id" | "nodeKey" | "sample">): Device {
  return {
    ...partial,
    id: randomBytes(8).toString("hex"),
    nodeKey: `sample-${randomBytes(8).toString("hex")}`,
    sample: true,
  };
}

export function sampleFleet(): Device[] {
  return [
    device({
      hostname: "ops-macbook-14",
      platform: "darwin",
      osName: "macOS",
      osVersion: "15.1",
      arch: "arm64",
      serial: "C02SAMPLE01",
      hardwareModel: "MacBook Pro 14-inch",
      cpu: "Apple M3 Pro",
      memoryMb: 36 * 1024,
      diskEncryption: true,
      firewall: true,
      ipAddresses: ["10.4.12.18"],
      username: "sam",
      uptimeSeconds: 86_400 * 4,
      software: [
        { name: "Google Chrome", version: "131.0.6778.86" },
        { name: "1Password", version: "8.10.48" },
        { name: "Slack", version: "4.41.105" },
      ],
      pendingUpdates: [{ name: "Google Chrome", current: "131.0.6778.86", available: "132.0.6834.83" }],
      patchInventory: "ok",
      fim: [
        {
          path: "/etc/ssh/sshd_config",
          sha256: "a".repeat(64),
          size: 3200,
          mtime: ago(12 * 24 * 60),
        },
      ],
      fimBaseline: [
        {
          path: "/etc/ssh/sshd_config",
          sha256: "a".repeat(64),
          size: 3200,
          mtime: ago(12 * 24 * 60),
        },
      ],
      enrolledAt: ago(40 * 24 * 60),
      lastSeen: ago(0.4),
    }),
    device({
      hostname: "finance-win-07",
      platform: "windows",
      osName: "Windows",
      osVersion: "11 23H2",
      arch: "x86_64",
      serial: "WIN-SAMPLE-07",
      hardwareModel: "ThinkPad T14s",
      cpu: "AMD Ryzen 7 PRO 7840U",
      memoryMb: 32 * 1024,
      diskEncryption: false,
      firewall: true,
      ipAddresses: ["10.4.18.41"],
      username: "priya",
      uptimeSeconds: 86_400 * 12,
      software: [
        { name: "Microsoft 365 Apps", version: "16.0.18227" },
        { name: "CrowdStrike Falcon", version: "7.18" },
      ],
      pendingUpdates: [
        { name: "Windows Security Update KB5048685", current: "installed", available: "pending" },
        { name: "CrowdStrike Falcon", current: "7.18", available: "7.22" },
      ],
      patchInventory: "ok",
      fim: [
        {
          path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
          sha256: "b".repeat(64),
          size: 824,
          mtime: ago(3 * 24 * 60),
        },
      ],
      fimBaseline: [
        {
          path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
          sha256: "b".repeat(64),
          size: 824,
          mtime: ago(3 * 24 * 60),
        },
      ],
      enrolledAt: ago(90 * 24 * 60),
      lastSeen: ago(0.8),
    }),
    device({
      hostname: "build-linux-03",
      platform: "linux",
      osName: "Ubuntu",
      osVersion: "22.04.5",
      arch: "x86_64",
      serial: "",
      hardwareModel: "Dell PowerEdge R660",
      cpu: "Intel Xeon Gold 6430",
      memoryMb: 128 * 1024,
      diskEncryption: true,
      firewall: false,
      ipAddresses: ["10.8.1.23"],
      username: "ci",
      uptimeSeconds: 86_400 * 41,
      software: [
        { name: "docker", version: "24.0.7" },
        { name: "git", version: "2.34.1" },
        { name: "python3", version: "3.10.12" },
        { name: "openssh-server", version: "8.9p1" },
        { name: "openssl", version: "3.0.2" },
      ],
      pendingUpdates: [
        { name: "git", current: "2.34.1", available: "2.34.1-1ubuntu1.12" },
        { name: "openssh-server", current: "8.9p1", available: "1:8.9p1-3ubuntu0.11" },
      ],
      patchInventory: "ok",
      fim: [
        {
          path: "/etc/ssh/sshd_config",
          sha256: "c".repeat(64),
          size: 3288,
          mtime: ago(40),
        },
        {
          path: "/etc/passwd",
          sha256: "d".repeat(64),
          size: 2104,
          mtime: ago(200 * 24 * 60),
        },
      ],
      fimBaseline: [
        {
          path: "/etc/ssh/sshd_config",
          sha256: "9".repeat(64),
          size: 3288,
          mtime: ago(200 * 24 * 60),
        },
        {
          path: "/etc/passwd",
          sha256: "d".repeat(64),
          size: 2104,
          mtime: ago(200 * 24 * 60),
        },
      ],
      enrolledAt: ago(200 * 24 * 60),
      lastSeen: ago(0.2),
    }),
    device({
      hostname: "design-imac",
      platform: "darwin",
      osName: "macOS",
      osVersion: "12.7.6",
      arch: "x86_64",
      serial: "C02SAMPLE88",
      hardwareModel: "iMac 27-inch 2020",
      cpu: "Intel Core i7",
      memoryMb: 16 * 1024,
      diskEncryption: true,
      firewall: null,
      ipAddresses: ["10.4.12.77"],
      username: "lee",
      uptimeSeconds: 86_400 * 2,
      software: [
        { name: "Figma", version: "124.0.2" },
        { name: "Adobe Photoshop", version: "25.0" },
      ],
      pendingUpdates: [{ name: "macOS", current: "12.7.6", available: "15.1" }],
      patchInventory: "ok",
      fim: [
        {
          path: "/etc/hosts",
          sha256: "e".repeat(64),
          size: 236,
          mtime: ago(8),
        },
      ],
      fimBaseline: [
        {
          path: "/etc/hosts",
          sha256: "8".repeat(64),
          size: 236,
          mtime: ago(400 * 24 * 60),
        },
      ],
      enrolledAt: ago(400 * 24 * 60),
      lastSeen: ago(18),
    }),
  ];
}

export function sampleFimEvents(devices: Device[]) {
  const linux = devices.find((d) => d.hostname === "build-linux-03");
  const imac = devices.find((d) => d.hostname === "design-imac");
  const events = [];
  if (linux) {
    events.push({
      id: randomBytes(6).toString("hex"),
      deviceId: linux.id,
      hostname: linux.hostname,
      path: "/etc/ssh/sshd_config",
      previous: "9".repeat(64),
      current: "c".repeat(64),
      detectedAt: ago(40),
      sample: true,
    });
  }
  if (imac) {
    events.push({
      id: randomBytes(6).toString("hex"),
      deviceId: imac.id,
      hostname: imac.hostname,
      path: "/etc/hosts",
      previous: "8".repeat(64),
      current: "e".repeat(64),
      detectedAt: ago(8),
      sample: true,
    });
  }
  return events;
}

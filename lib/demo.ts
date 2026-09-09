import { randomBytes } from "node:crypto";
import type { Device } from "./types";

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
        { name: "docker", version: "27.3.1" },
        { name: "git", version: "2.34.1" },
        { name: "python3", version: "3.10.12" },
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
        { name: "Adobe Photoshop", version: "26.0" },
      ],
      enrolledAt: ago(400 * 24 * 60),
      lastSeen: ago(18),
    }),
  ];
}

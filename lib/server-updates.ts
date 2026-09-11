import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { join } from "node:path";

import { dataDir } from "./data-paths.ts";

export const DEFAULT_UPDATE_REPO = "WASP512/defendsec";
const REQUIRED_RELEASE_ASSETS = [
  "SHA256SUMS",
  "VERSION",
  "defendsec-console.tar.gz",
  "defendsec-apid-linux-amd64",
  "defendsec-apid-linux-arm64",
  "defendsec-agentd-linux-amd64",
  "defendsec-agentd-linux-arm64",
  "install-agent.sh",
  "update-server.sh",
] as const;

type GitHubAsset = {
  name?: string;
  browser_download_url?: string;
};

export type GitHubRelease = {
  tag_name?: string;
  name?: string;
  body?: string;
  html_url?: string;
  published_at?: string;
  draft?: boolean;
  prerelease?: boolean;
  assets?: GitHubAsset[];
};

export type UpdateStatus = {
  state: "idle" | "downloading" | "installing" | "completed" | "failed";
  message: string;
  version?: string;
  updatedAt?: string;
};

export type AgentReleaseArtifact = {
  arch: "amd64" | "arm64";
  version: string;
  url: string;
  sha256: string;
};

export type ServerUpdateState = {
  currentVersion: string;
  latestVersion?: string;
  tag?: string;
  releaseName?: string;
  notes?: string;
  releaseURL?: string;
  publishedAt?: string;
  updateAvailable: boolean;
  canApply: boolean;
  unavailableReason?: string;
  missingAssets: string[];
  agentArtifacts: AgentReleaseArtifact[];
  status: UpdateStatus;
  repo: string;
};

export function normalizeVersion(value: string) {
  return value.trim().replace(/^v(?=\d)/i, "");
}

function semverParts(value: string) {
  const match = normalizeVersion(value).match(/^(\d+)\.(\d+)\.(\d+)(?:[-+]([0-9A-Za-z.-]+))?$/);
  if (!match) return null;
  return {
    numbers: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] ?? "",
  };
}

export function compareVersions(left: string, right: string) {
  const a = semverParts(left);
  const b = semverParts(right);
  if (!a || !b) return normalizeVersion(left) === normalizeVersion(right) ? 0 : null;
  for (let index = 0; index < 3; index += 1) {
    if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] < b.numbers[index] ? -1 : 1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease.localeCompare(b.prerelease);
}

export function parseRelease(release: GitHubRelease) {
  const tag = release.tag_name?.trim() ?? "";
  if (!tag || release.draft || release.prerelease) {
    throw new Error("No stable release is available");
  }
  const assets = new Map(
    (release.assets ?? [])
      .filter((asset) => asset.name && asset.browser_download_url)
      .map((asset) => [asset.name as string, asset.browser_download_url as string]),
  );
  return {
    tag,
    version: normalizeVersion(tag),
    name: release.name?.trim() || tag,
    notes: release.body?.trim() ?? "",
    url: release.html_url?.trim() ?? "",
    publishedAt: release.published_at?.trim() ?? "",
    assets,
    missingAssets: REQUIRED_RELEASE_ASSETS.filter((name) => !assets.has(name)),
  };
}

export function parseChecksums(value: string) {
  const checksums = new Map<string, string>();
  for (const line of value.split(/\r?\n/)) {
    const match = line.trim().match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (match) checksums.set(match[2], match[1].toLowerCase());
  }
  return checksums;
}

async function agentArtifacts(
  version: string,
  assets: Map<string, string>,
): Promise<AgentReleaseArtifact[]> {
  const sumsURL = assets.get("SHA256SUMS");
  if (!sumsURL) return [];
  try {
    const response = await fetch(sumsURL, {
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) return [];
    const sums = parseChecksums(await response.text());
    return (["amd64", "arm64"] as const).flatMap((arch) => {
      const name = `defendsec-agentd-linux-${arch}`;
      const url = assets.get(name);
      const sha256 = sums.get(name);
      return url && sha256 ? [{ arch, version, url, sha256 }] : [];
    });
  } catch {
    return [];
  }
}

async function exists(path: string) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function currentVersion() {
  for (const path of ["/opt/defendsec/VERSION", join(process.cwd(), "VERSION")]) {
    try {
      const value = (await readFile(path, "utf8")).trim();
      if (value) return value;
    } catch {
      // Try the next source.
    }
  }
  const configured = process.env.DEFENDSEC_VERSION?.trim();
  if (configured) return configured;
  return "dev";
}

async function updateStatus(): Promise<UpdateStatus> {
  try {
    const raw = await readFile(join(dataDir(), "update-status.json"), "utf8");
    const parsed = JSON.parse(raw) as Partial<UpdateStatus>;
    if (
      parsed.state === "downloading" ||
      parsed.state === "installing" ||
      parsed.state === "completed" ||
      parsed.state === "failed"
    ) {
      return {
        state: parsed.state,
        message: parsed.message || "Update status changed",
        version: parsed.version,
        updatedAt: parsed.updatedAt,
      };
    }
  } catch {
    // No update has been attempted.
  }
  return { state: "idle", message: "No update is running" };
}

async function latestRelease(repo: string): Promise<GitHubRelease> {
  const fixture = process.env.DEFENDSEC_UPDATE_RELEASE_FILE?.trim();
  if (fixture) {
    return JSON.parse(await readFile(fixture, "utf8")) as GitHubRelease;
  }
  const response = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "DefendSec-Update-Checker",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    cache: "no-store",
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok) throw new Error(`Release service returned HTTP ${response.status}`);
  return (await response.json()) as GitHubRelease;
}

export async function getServerUpdateState(): Promise<ServerUpdateState> {
  const repo = process.env.DEFENDSEC_UPDATE_REPO?.trim() || DEFAULT_UPDATE_REPO;
  const current = await currentVersion();
  const status = await updateStatus();
  try {
    const release = parseRelease(await latestRelease(repo));
    const agents = await agentArtifacts(release.version, release.assets);
    const comparison = compareVersions(current, release.version);
    const updateAvailable = comparison === null
      ? current !== "dev" && normalizeVersion(current) !== release.version
      : comparison < 0;
    const helperReady =
      process.platform === "linux" &&
      (await exists("/usr/local/sbin/defendsec-update")) &&
      (await exists("/etc/sudoers.d/defendsec-update"));
    const canApply = updateAvailable && release.missingAssets.length === 0 && helperReady;
    let unavailableReason: string | undefined;
    if (current === "dev") unavailableReason = "Development builds cannot be upgraded in place.";
    else if (release.missingAssets.length > 0) unavailableReason = "The release is missing required server artifacts.";
    else if (!helperReady) unavailableReason = "Re-run the server installer once to enable one-click updates.";
    return {
      currentVersion: current,
      latestVersion: release.version,
      tag: release.tag,
      releaseName: release.name,
      notes: release.notes,
      releaseURL: release.url,
      publishedAt: release.publishedAt,
      updateAvailable,
      canApply,
      unavailableReason,
      missingAssets: release.missingAssets,
      agentArtifacts: agents,
      status,
      repo,
    };
  } catch {
    return {
      currentVersion: current,
      updateAvailable: false,
      canApply: false,
      unavailableReason: "The release service is unavailable. Existing services are unaffected.",
      missingAssets: [],
      agentArtifacts: [],
      status,
      repo,
    };
  }
}


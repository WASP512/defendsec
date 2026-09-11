export const REQUIRED_RELEASE_ASSETS = [
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


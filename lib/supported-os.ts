// Which operating systems count as supported (the "Supported OS" policy).
//
// DefendSec supports Linux — Ubuntu, Debian, Fedora, Red Hat Enterprise
// Linux and its rebuilds, and openSUSE — and Windows. The floors below are
// the oldest releases their vendors still patch; update them as releases
// reach end of life. Anything else is "unknown", not "unsupported": we do
// not know its support status, and saying it fails would be a guess.

export type Distro = "ubuntu" | "debian" | "fedora" | "rhel" | "opensuse" | "opensuse-tumbleweed";

// Minimum supported release per distro, as [major, minor].
export const SUPPORTED_FLOOR: Record<Exclude<Distro, "opensuse-tumbleweed">, [number, number]> = {
  ubuntu: [22, 4], // 22.04 LTS and later
  debian: [12, 0], // bookworm and later
  fedora: [43, 0], // Fedora supports the two newest releases
  rhel: [8, 0], // RHEL 8 and 9 (and 10); includes Rocky, Alma, CentOS Stream
  opensuse: [16, 0], // Leap 16.0 and later
};

// The first Windows build still supported: Server 2022 (20348). Windows 11
// is 22000+, Server 2025 is 26100. Windows 10 (19045) reached end of support
// in October 2025.
export const WINDOWS_MIN_BUILD = 20348;

// distroOf maps os-release NAME (what the agent reports as osName).
export function distroOf(osName: string): Distro | null {
  const n = osName.toLowerCase();
  if (n.includes("ubuntu")) return "ubuntu";
  if (n.includes("debian")) return "debian";
  if (n.includes("fedora")) return "fedora";
  if (n.includes("tumbleweed")) return "opensuse-tumbleweed";
  if (n.includes("opensuse") || n.includes("suse")) return "opensuse";
  if (
    n.includes("red hat") ||
    n.includes("rhel") ||
    n.includes("rocky") ||
    n.includes("almalinux") ||
    n.includes("centos stream")
  )
    return "rhel";
  return null;
}

function parseVersion(v: string): [number, number] | null {
  const m = v.trim().match(/^(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2] ?? 0)];
}

function atLeast(v: [number, number], floor: [number, number]) {
  return v[0] > floor[0] || (v[0] === floor[0] && v[1] >= floor[1]);
}

export type Floors = {
  distros: Record<Exclude<Distro, "opensuse-tumbleweed">, [number, number]>;
  windowsBuild: number;
};

// floorsFrom applies DEFENDSEC_SUPPORTED_OS overrides, so the minimums can
// move as releases reach end of life without waiting for a DefendSec
// release: "fedora=44,rhel=9,windows=26100". Malformed entries are ignored
// rather than guessed at; the defaults stand.
export function floorsFrom(spec: string | undefined): Floors {
  const floors: Floors = { distros: { ...SUPPORTED_FLOOR }, windowsBuild: WINDOWS_MIN_BUILD };
  for (const part of (spec ?? "").split(",")) {
    const [key, value] = part.split("=").map((x) => x?.trim().toLowerCase() ?? "");
    if (!key || !value) continue;
    if (key === "windows") {
      const n = Number(value);
      if (Number.isInteger(n) && n > 0) floors.windowsBuild = n;
      continue;
    }
    if (key in floors.distros) {
      const v = parseVersion(value);
      if (v) floors.distros[key as keyof Floors["distros"]] = v;
    }
  }
  return floors;
}

function currentFloors(): Floors {
  const spec = typeof process !== "undefined" ? process.env?.DEFENDSEC_SUPPORTED_OS : undefined;
  return floorsFrom(spec);
}

// supportedOs returns true or false when it knows, and null when it does not.
export function supportedOs(
  d: { platform: string; osName: string; osVersion: string },
  floors: Floors = currentFloors(),
): boolean | null {
  if (d.platform === "windows") {
    // Version is "10.0.<build>" on every current Windows.
    const build = Number(d.osVersion.split(".")[2]);
    if (!Number.isFinite(build) || build === 0) return null;
    return build >= floors.windowsBuild;
  }
  if (d.platform !== "linux") return null;
  const distro = distroOf(d.osName);
  if (!distro) return null;
  if (distro === "opensuse-tumbleweed") return true; // rolling release
  const v = parseVersion(d.osVersion);
  if (!v) return null;
  return atLeast(v, floors.distros[distro]);
}

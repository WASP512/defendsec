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

// Windows is judged by the date Microsoft stops shipping security updates for
// the build (below), not by a floor: a floor on the build number called Server
// 2016 and 2019, supported until 2027 and 2029, unsupported. This constant is
// only the default of the optional DEFENDSEC_SUPPORTED_OS override
// ("windows=<build>"), which, when an operator sets it, replaces the dates.
export const WINDOWS_MIN_BUILD = 20348;

// End of security updates by build number, from Microsoft's lifecycle data as
// published on endoflife.date (checked 2026-10-24). "w" is Home and Pro, "e" is
// Enterprise and Education; a build with one date has the same for both. "lts"
// is the Long-Term Servicing Channel of that build. Server builds are listed
// apart because a build number is shared with a client release (17763 is Windows
// 10 1809 and Server 2019). Dates are when updates stop, not mainstream support,
// and a paid Extended Security Update programme (Windows 10, Server 2012) is not
// counted: DefendSec cannot see whether one was bought.
type Eos = { w: string; e?: string; lts?: string };
const WINDOWS_CLIENT_EOS: Record<number, Eos> = {
  28000: { w: "2028-03-14", e: "2029-03-13" }, // 11 26H1
  26300: { w: "2028-10-10", e: "2029-10-09" }, // 11 26H2
  26200: { w: "2027-10-12", e: "2028-10-10" }, // 11 25H2
  26100: { w: "2026-10-13", e: "2027-10-12", lts: "2029-10-09" }, // 11 24H2
  22631: { w: "2025-11-11", e: "2026-11-10" }, // 11 23H2
  22621: { w: "2024-10-08", e: "2025-10-14" }, // 11 22H2
  22000: { w: "2023-10-10", e: "2024-10-08" }, // 11 21H2
  19045: { w: "2025-10-14" }, // 10 22H2
  19044: { w: "2023-06-13", e: "2024-06-11", lts: "2027-01-12" }, // 10 21H2
  19043: { w: "2022-12-13" }, // 10 21H1
  19042: { w: "2022-05-10", e: "2023-05-09" }, // 10 20H2
  19041: { w: "2021-12-14" }, // 10 2004
  18363: { w: "2021-05-11", e: "2022-05-10" }, // 10 1909
  18362: { w: "2020-12-08" }, // 10 1903
  17763: { w: "2020-11-10", e: "2021-05-11", lts: "2029-01-09" }, // 10 1809
  17134: { w: "2019-11-12", e: "2021-05-11" }, // 10 1803
  16299: { w: "2019-04-09", e: "2020-10-13" }, // 10 1709
  15063: { w: "2018-10-09", e: "2019-10-08" }, // 10 1703
  14393: { w: "2018-04-10", e: "2019-04-09", lts: "2026-10-13" }, // 10 1607
  10586: { w: "2017-10-10" }, // 10 1511
  10240: { w: "2017-05-09", lts: "2025-10-14" }, // 10 1507
  9600: { w: "2023-01-10" }, // 8.1
  9200: { w: "2016-01-12" }, // 8
  7601: { w: "2020-01-14" }, // 7 SP1
  6002: { w: "2017-04-11" }, // Vista SP2
  2600: { w: "2014-04-08" }, // XP SP3
};
const WINDOWS_SERVER_EOS: Record<number, string> = {
  26100: "2034-11-14", // 2025
  20348: "2031-10-14", // 2022
  17763: "2029-01-09", // 2019
  14393: "2027-01-12", // 2016
  9600: "2023-10-10", // 2012 R2
  9200: "2023-10-10", // 2012
  7601: "2020-01-14", // 2008 R2 SP1
  6003: "2020-01-14", // 2008 SP2
  6002: "2020-01-14", // 2008
  3790: "2015-07-14", // 2003
};

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
  // True when the operator set windows=<build>: that floor then replaces the
  // end-of-support dates.
  windowsOverride: boolean;
};

// floorsFrom applies DEFENDSEC_SUPPORTED_OS overrides, so the minimums can
// move as releases reach end of life without waiting for a DefendSec
// release: "fedora=44,rhel=9,windows=26100". Malformed entries are ignored
// rather than guessed at; the defaults stand.
export function floorsFrom(spec: string | undefined): Floors {
  const floors: Floors = { distros: { ...SUPPORTED_FLOOR }, windowsBuild: WINDOWS_MIN_BUILD, windowsOverride: false };
  for (const part of (spec ?? "").split(",")) {
    const [key, value] = part.split("=").map((x) => x?.trim().toLowerCase() ?? "");
    if (!key || !value) continue;
    if (key === "windows") {
      const n = Number(value);
      if (Number.isInteger(n) && n > 0) {
        floors.windowsBuild = n;
        floors.windowsOverride = true;
      }
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

function windowsBuildOf(osVersion: string): number | null {
  // Version is "<major>.<minor>.<build>" on every Windows.
  const build = Number(osVersion.split(".")[2]);
  return Number.isFinite(build) && build > 0 ? build : null;
}

export type WindowsEos = {
  /** The date security updates stop (YYYY-MM-DD) for the build, or null if the date depends on an edition we cannot read from the name. */
  date: string | null;
  /** When the date depends on the edition and the name does not say which, both dates. */
  range: [string, string] | null;
  /** What the date is for, for display: "Server", "Home/Pro", "Enterprise/Education", "LTSC". */
  basis: string;
};

/**
 * End of security updates for a Windows device, from its caption (which names the
 * edition) and "major.minor.build". Null when the build is not in the table: an
 * unknown build is unknown, not unsupported.
 */
export function windowsEndOfSupport(osName: string, osVersion: string): WindowsEos | null {
  const build = windowsBuildOf(osVersion);
  if (build === null) return null;
  const name = osName.toLowerCase();
  if (name.includes("server")) {
    const date = WINDOWS_SERVER_EOS[build];
    return date ? { date, range: null, basis: "Server" } : null;
  }
  const eos = WINDOWS_CLIENT_EOS[build];
  if (!eos) return null;
  if (eos.lts && /ltsc|ltsb|iot/.test(name)) return { date: eos.lts, range: null, basis: "LTSC" };
  if (!eos.e || eos.e === eos.w) return { date: eos.w, range: null, basis: "all editions" };
  if (/enterprise|education/.test(name)) return { date: eos.e, range: null, basis: "Enterprise/Education" };
  if (/\b(home|pro|professional)\b/.test(name)) return { date: eos.w, range: null, basis: "Home/Pro" };
  // The caption does not name an edition: the date is one of two.
  return { date: null, range: [eos.w, eos.e], basis: "edition not named" };
}

// supportedOs returns true or false when it knows, and null when it does not.
export function supportedOs(
  d: { platform: string; osName: string; osVersion: string },
  floors: Floors = currentFloors(),
  now: Date = new Date(),
): boolean | null {
  if (d.platform === "windows") {
    if (floors.windowsOverride) {
      const build = windowsBuildOf(d.osVersion);
      return build === null ? null : build >= floors.windowsBuild;
    }
    const eos = windowsEndOfSupport(d.osName, d.osVersion);
    if (!eos) return null;
    const today = now.toISOString().slice(0, 10);
    if (eos.date) return today <= eos.date;
    if (eos.range) {
      const [early, late] = eos.range;
      if (today <= early) return true;
      if (today > late) return false;
      return null; // between the two dates, and the caption does not say which edition this is
    }
    return null;
  }
  if (d.platform !== "linux") return null;
  const distro = distroOf(d.osName);
  if (!distro) return null;
  if (distro === "opensuse-tumbleweed") return true; // rolling release
  const v = parseVersion(d.osVersion);
  if (!v) return null;
  return atLeast(v, floors.distros[distro]);
}

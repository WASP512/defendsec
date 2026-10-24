// Windows end-of-support from the endoflife.date calendar, keyed on edition and build.
//
// A build number alone cannot say whether a Windows host is supported: client,
// server and LTSC editions share builds and have different dates.
//
//   14393  Windows Server 2016 (security support until 2027-01-12) and
//          Windows 10 LTSB 2016 (ended 2026-10-13)
//   17763  Windows Server 2019 and Windows 10 LTSC 2019 (both until 2029-01-09),
//          but Windows 10 1809 Enterprise/Pro (ended 2021)
//   19044  Windows 10 LTSC 2021 (until 2027-01-12) and 21H2 Enterprise/Pro (ended 2024)
//   19045  Windows 10 22H2 (ended 2025-10-14)
//
// The calendar is the `windows` and `windows-server` products of endoflife.date,
// loaded by the feed pipeline (GET /v1/lifecycle/os). A cycle is found by its
// latest build; the edition picks among the cycles that share it:
//
//   windows-server  "2016", "2019", ...      Server editions; "-sac" cycles only for ACor editions
//   windows         "...-w"                  Home, Pro, Pro Education, Pro for Workstations
//                   "...-e"                  Enterprise, Education, IoT Enterprise
//                   "...-e-lts"              Enterprise LTSC / LTSB (EditionID EnterpriseS)
//                   "...-iot-lts"            IoT Enterprise LTSC
//                   no suffix                one date for every edition ("10-22h2")
//
// What this answers is whether the vendor still issues security updates for the
// release. Paid extended security updates (the feed's eoesFrom) do not count:
// Windows 10 22H2 has them until 2028 and is reported unsupported.
//
// A host whose edition cannot be read is judged on every cycle its build could
// be. If they agree the answer stands; if they disagree it is *unknown*, never
// "unsupported".

export type OsRelease = {
  product: string;
  cycle: string;
  label: string;
  eoasFrom: string;
  eolFrom: string;
  eoesFrom: string;
  isLts: boolean;
  /** Newest build of the cycle, "10.0.14393". */
  latest: string;
};

export type WindowsKind = "server" | "server-sac" | "client";
export type ClientTrack = "w" | "e" | "ltsc" | "iot-ltsc";

export type WindowsEdition = {
  kind: WindowsKind | null;
  track: ClientTrack | null;
  /** Where the answer came from: the agent's EditionID, or the OS caption. */
  source: "edition" | "caption" | null;
};

/** Read what is known about a Windows host's edition. EditionID wins; the OS caption fills in when the agent predates it. */
export function windowsEdition(editionId: string | undefined, caption: string | undefined): WindowsEdition {
  const id = (editionId ?? "").trim().toLowerCase();
  if (id) {
    if (id.startsWith("server")) return { kind: id.endsWith("acor") ? "server-sac" : "server", track: null, source: "edition" };
    if (id === "enterprises" || id === "enterprisesn") return { kind: "client", track: "ltsc", source: "edition" };
    if (id === "iotenterprises") return { kind: "client", track: "iot-ltsc", source: "edition" };
    if (/^(core|professional)/.test(id)) return { kind: "client", track: "w", source: "edition" };
    if (/^(enterprise|education|iotenterprise)/.test(id)) return { kind: "client", track: "e", source: "edition" };
    return { kind: null, track: null, source: null }; // an EditionID this table does not know
  }
  const c = (caption ?? "").toLowerCase();
  if (/\bserver\b/.test(c)) return { kind: "server", track: null, source: "caption" };
  if (/ltsc|ltsb/.test(c)) return { kind: "client", track: /\biot\b/.test(c) ? "iot-ltsc" : "ltsc", source: "caption" };
  if (/\b(home|pro|pro education|workstation)\b/.test(c)) return { kind: "client", track: "w", source: "caption" };
  if (/enterprise|education|\biot\b/.test(c)) return { kind: "client", track: "e", source: "caption" };
  return { kind: null, track: null, source: null };
}

/** The build number of a Windows version string: "10.0.17763" gives 17763, "6.3.9600" gives 9600. */
export function windowsBuild(version: string): number | null {
  const parts = version.trim().split(".");
  if (parts.length < 3) return null;
  const n = Number(parts[2]);
  return Number.isInteger(n) && n > 0 ? n : null;
}

type Variant = "w" | "e" | "ltsc" | "iot-ltsc" | "iot-core" | "common" | "sac" | "server";

function variantOf(r: OsRelease): Variant {
  const c = r.cycle.toLowerCase();
  if (r.product === "windows-server") return /-(sac|ac)$/.test(c) ? "sac" : "server";
  if (c.endsWith("-iot-lts")) return "iot-ltsc";
  if (c.endsWith("-e-lts")) return "ltsc";
  if (c.endsWith("-iot")) return "iot-core";
  if (c.endsWith("-e")) return "e";
  if (c.endsWith("-w")) return "w";
  return "common";
}

function buildOf(r: OsRelease): number | null {
  return windowsBuild(r.latest);
}

export type OsSupport = {
  /** true: the vendor still issues security updates. false: it does not. null: cannot tell. */
  state: boolean | null;
  /** One line an operator can read next to the verdict. */
  reason: string;
  /** The calendar cycles the verdict rests on, "windows-server 2016". */
  cycles: string[];
  edition: WindowsEdition;
};

function day(asOf: Date): string {
  return asOf.toISOString().slice(0, 10);
}

function name(r: OsRelease): string {
  return `${r.product === "windows-server" ? "Windows Server" : "Windows"} ${r.cycle}`;
}

function verdict(r: OsRelease, today: string): boolean | null {
  if (!r.eolFrom) return null; // no end date in the calendar: not a verdict
  return today < r.eolFrom; // eolFrom is the first day without security updates
}

function say(r: OsRelease, ok: boolean): string {
  return ok ? `${name(r)}: security updates until ${r.eolFrom}` : `${name(r)}: security updates ended ${r.eolFrom}`;
}

/**
 * Whether a Windows host's release still gets vendor security updates on asOf.
 * calendar is the windows and windows-server rows of the endoflife feed.
 */
export function windowsSupport(
  d: { osName: string; osVersion: string; osEdition?: string },
  calendar: OsRelease[],
  asOf: Date = new Date(),
): OsSupport {
  const edition = windowsEdition(d.osEdition, d.osName);
  const unknown = (reason: string, cycles: string[] = []): OsSupport => ({ state: null, reason, cycles, edition });
  const build = windowsBuild(d.osVersion);
  if (build === null) return unknown("The Windows build number was not reported");
  if (calendar.length === 0) return unknown("The release calendar has not been loaded (run defendsec-feeds sync)");
  const today = day(asOf);

  let rows = calendar.filter((r) => (r.product === "windows" || r.product === "windows-server") && buildOf(r) === build);
  if (rows.length === 0) return unknown(`Build ${build} is not in the release calendar`);

  // Narrow by what is known about the edition.
  if (edition.kind === "server") rows = rows.filter((r) => variantOf(r) === "server");
  else if (edition.kind === "server-sac") rows = rows.filter((r) => variantOf(r) === "sac");
  else if (edition.kind === "client") {
    rows = rows.filter((r) => {
      const v = variantOf(r);
      return v === edition.track || v === "common";
    });
  } else {
    // Edition unknown: every cycle this build could be, except the channels no plain
    // host is on (semi-annual server releases, IoT Core).
    rows = rows.filter((r) => !["sac", "iot-core"].includes(variantOf(r)));
  }
  if (rows.length === 0) return unknown(`No release in the calendar matches build ${build} for this edition`);

  const verdicts = rows.map((r) => ({ r, ok: verdict(r, today) }));
  if (verdicts.some((v) => v.ok === null)) {
    return unknown(`The calendar gives no end date for ${verdicts.map((v) => name(v.r)).join(", ")}`, verdicts.map((v) => name(v.r)));
  }
  const yes = verdicts.filter((v) => v.ok);
  const no = verdicts.filter((v) => !v.ok);
  const cycles = verdicts.map((v) => name(v.r));
  if (no.length === 0 || yes.length === 0) {
    const ok = no.length === 0;
    // Several cycles that agree: report the one that ends last, the host's best case.
    const pick = [...verdicts].sort((a, b) => b.r.eolFrom.localeCompare(a.r.eolFrom))[0].r;
    return { state: ok, reason: say(pick, ok) + (edition.source === "caption" ? " (edition read from the OS caption)" : ""), cycles, edition };
  }
  const named = (list: typeof verdicts) => list.map((v) => name(v.r)).join(", ");
  return unknown(
    `Edition not reported, and build ${build} is both supported (${named(yes)}) and past support (${named(no)})`,
    cycles,
  );
}

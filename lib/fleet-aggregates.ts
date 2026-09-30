import { allFindings } from "./advisories.ts";
import { fleetVersion } from "./mtls-agents.ts";
import { policySummary } from "./policies.ts";
import type { Device, FindingTriage } from "./types.ts";

// Fleet-wide aggregates for the overview, Policies and Advisories pages.
//
// They match every host's software against the advisory catalog, which at
// 10,000 hosts takes seconds. The inputs change only when the fleet export
// is rewritten (at most every 30 seconds) or someone triages a finding, so
// the result is reused until one of those changes (roadmap 5.5).

type Aggregates = {
  policies: ReturnType<typeof policySummary>;
  findings: ReturnType<typeof allFindings>;
};

let cache: { key: string; value: Aggregates } | null = null;
let pending: string | null = null;

// Recomputes off the request path when a previous result exists: the
// caller gets that result now, and the next request gets the new one.
function revalidate(key: string, compute: () => void) {
  if (pending === key) return;
  pending = key;
  setImmediate(() => {
    try {
      compute();
    } finally {
      pending = null;
    }
  });
}

function keyFor(fleet: Device[], triages: FindingTriage[]): string {
  // Hosts from the console's own store are few; their last-seen times are
  // part of the key so a check-in is reflected immediately.
  const local = fleet
    .filter((d) => !d.mtlsDeviceId || d.sample)
    .map((d) => `${d.id}@${d.lastSeen}`)
    .join(",");
  const tri = triages.map((t) => `${t.key}=${t.status}`).join(",");
  return `${fleetVersion()}|${fleet.length}|${local}|${tri}`;
}

function sameTriage(a: string, b: string): boolean {
  return a.slice(a.lastIndexOf("|")) === b.slice(b.lastIndexOf("|"));
}

export function fleetAggregates(fleet: Device[], triages: FindingTriage[]): Aggregates {
  const key = keyFor(fleet, triages);
  if (cache?.key === key) return cache.value;
  const compute = () => {
    cache = { key, value: { policies: policySummary(fleet, [], triages), findings: allFindings(fleet, triages) } };
  };
  // A triage change must show at once — the operator just made it — so
  // only a fleet refresh is served stale.
  if (cache && sameTriage(cache.key, key)) {
    revalidate(key, compute);
    return cache.value;
  }
  compute();
  return cache!.value;
}

let findingsCache: { key: string; value: ReturnType<typeof allFindings> } | null = null;

// fleetFindings is allFindings against a given catalog (the Advisories page
// uses the ingested one), cached the same way. The catalog is part of the
// key by size and its ids at each end, which change on every ingest.
export function fleetFindings(
  fleet: Device[],
  triages: FindingTriage[],
  advisories: Parameters<typeof allFindings>[2] & object,
): ReturnType<typeof allFindings> {
  const cat = `${advisories.length}:${advisories[0]?.id ?? ""}:${advisories[advisories.length - 1]?.id ?? ""}`;
  const key = `${keyFor(fleet, triages)}|${cat}`;
  if (findingsCache?.key === key) return findingsCache.value;
  const value = allFindings(fleet, triages, advisories);
  findingsCache = { key, value };
  return value;
}

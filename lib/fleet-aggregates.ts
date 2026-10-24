import { fleetVersion } from "./mtls-agents.ts";
import { policySummary } from "./policies.ts";
import { seriousOpen, type DeviceFindingsSummary } from "./findings-model.ts";
import type { Device, FindingTriage } from "./types.ts";

// Fleet-wide aggregates for the overview and Policies pages.
//
// Policy evaluation walks every host, which at 10,000 hosts takes seconds. The
// inputs change only when the fleet export is rewritten (at most every 30
// seconds), when someone triages a finding, or when the control plane re-matches
// a host, so the result is reused until one of those changes (roadmap 5.5).
//
// Findings are not computed here: apid matches each host against the distro's
// advisory ranges and this takes its per-host summary (GET /v1/findings/summary).

type Aggregates = {
  policies: ReturnType<typeof policySummary>;
  /** Open high/critical/KEV findings with a fix available, fleet-wide. Null if
   *  the control plane could not be asked. */
  serious: number | null;
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

function vulnKey(vulns: Map<string, DeviceFindingsSummary> | null): string {
  if (!vulns) return "unavailable";
  let latest = "";
  for (const v of vulns.values()) if (v.matchedAt > latest) latest = v.matchedAt;
  return `${vulns.size}@${latest}`;
}

function keyFor(
  fleet: Device[],
  triages: FindingTriage[],
  vulns: Map<string, DeviceFindingsSummary> | null,
): string {
  // Hosts from the console's own store are few; their last-seen times are
  // part of the key so a check-in is reflected immediately.
  const local = fleet
    .filter((d) => !d.mtlsDeviceId || d.sample)
    .map((d) => `${d.id}@${d.lastSeen}`)
    .join(",");
  const tri = triages.map((t) => `${t.key}=${t.status}`).join(",");
  return `${fleetVersion()}|${fleet.length}|${local}|${vulnKey(vulns)}|${tri}`;
}

function sameTriage(a: string, b: string): boolean {
  return a.slice(a.lastIndexOf("|")) === b.slice(b.lastIndexOf("|"));
}

export function fleetAggregates(
  fleet: Device[],
  triages: FindingTriage[],
  vulns: Map<string, DeviceFindingsSummary> | null,
): Aggregates {
  const key = keyFor(fleet, triages, vulns);
  if (cache?.key === key) return cache.value;
  const compute = () => {
    let serious: number | null = null;
    if (vulns) {
      serious = 0;
      for (const v of vulns.values()) serious += seriousOpen(v, triages);
    }
    cache = { key, value: { policies: policySummary(fleet, [], triages, vulns), serious } };
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

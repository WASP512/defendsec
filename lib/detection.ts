// Shapes and presentation order for the detection coverage matrix and the
// forwarding posture (roadmap 3.4 and 3.6).
//
// Nothing here is computed in the console. The control plane owns which rules
// are loaded, which event kinds it has actually seen, and where records are
// being sent; a second opinion assembled in the browser would drift from the
// one the operator is actually running. What this module does own is the order
// things are shown in, which is why it is separate from the fetching in
// detection-server.ts: the ordering rules are worth testing on their own.

export type SkippedRule = {
  source: string;
  reason: string;
};

export type EventGap = {
  hostname?: string;
  droppedTotal: number;
  lastGap?: number;
  lastGapAt?: string;
  received: number;
  lastEventAt?: string;
  sensor?: string;
};

export type DetectionCoverage = {
  rules: number;
  skipped?: SkippedRule[];
  byLevel: Record<string, number>;
  byCategory: Record<string, number>;
  techniques: string[];
  tactics: string[];
  observedKinds: string[];
  unobservedKinds: string[];
  gaps?: Record<string, EventGap>;
  caveats: string[];
};

export type DestinationStatus = {
  name: string;
  sent: number;
  failed: number;
  lastError?: string;
  lastErrorAt?: string;
  lastSentAt?: string;
  healthy: boolean;
};

export type ForwardingStatus = {
  enabled: boolean;
  accepted: number;
  dropped: number;
  sent: number;
  failed: number;
  queued: number;
  capacity: number;
  destinations?: DestinationStatus[];
  detail: string;
};

// Levels worst first, for the same reason the compliance page orders statuses
// worst first: a reader who stops after one screen should have seen the part
// that matters.
export const LEVEL_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

export function orderedLevels(
  byLevel: Record<string, number>,
): { level: string; count: number }[] {
  const seen = new Set(Object.keys(byLevel));
  const out: { level: string; count: number }[] = [];
  for (const level of LEVEL_ORDER) {
    if (seen.has(level)) {
      out.push({ level, count: byLevel[level] });
      seen.delete(level);
    }
  }
  for (const level of [...seen].sort()) {
    out.push({ level, count: byLevel[level] });
  }
  return out;
}

// A category with rules but no observed events is the interesting cell: the
// rules exist, and they cannot fire. Callers render those first.
export type CategoryRow = {
  category: string;
  rules: number;
  observed: boolean;
};

export function categoryRows(coverage: DetectionCoverage): CategoryRow[] {
  const observed = new Set(coverage.observedKinds);
  const categories = new Set([
    ...Object.keys(coverage.byCategory),
    ...coverage.observedKinds,
    ...coverage.unobservedKinds,
  ]);
  const rows = [...categories].map((category) => ({
    category,
    rules: coverage.byCategory[category] ?? 0,
    observed: observed.has(category),
  }));
  // Blind spots first: rules that cannot fire, then unwatched kinds, then
  // categories with no rules at all, then the working ones.
  const rank = (r: CategoryRow) => {
    if (r.rules > 0 && !r.observed) return 0;
    if (r.rules === 0 && r.observed) return 1;
    if (r.rules === 0) return 2;
    return 3;
  };
  rows.sort(
    (a, b) => rank(a) - rank(b) || a.category.localeCompare(b.category),
  );
  return rows;
}

// Pure logic for the feed-age banner on the Advisories page. No imports from
// the app, so it runs under `node --test` like the other lib/*.test.ts files.

export type FeedStatus = {
  name: string;
  kind: string;
  url: string;
  lastSuccess: string | null;
  lastAttempt: string | null;
  /** Seconds since the feed was last confirmed current and loaded; null if never. */
  ageSeconds: number | null;
  stale: boolean;
  recordCount: number;
  snapshotId: number | null;
  sha256: string;
  lastError: string;
};

/** The body of GET /v1/feeds. */
export type FeedsResponse = {
  feeds: FeedStatus[];
  generatedAt: string;
  staleAfterSeconds: number;
  anyStale: boolean;
  oldestAgeSeconds: number | null;
  latestSnapshotId: number | null;
};

/** red = something is stale; amber = we cannot say it is current; ok = current. */
export type BannerTone = "red" | "amber" | "ok";

export type FeedBanner = {
  tone: BannerTone;
  title: string;
  detail: string;
};

export const STALE_AFTER_SECONDS = 7 * 24 * 60 * 60;

/** "3 hours", "8 days": the largest whole unit, singular when it is 1. */
export function describeAge(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const units: [string, number][] = [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [name, size] of units) {
    if (s >= size) {
      const n = Math.floor(s / size);
      return `${n} ${name}${n === 1 ? "" : "s"}`;
    }
  }
  return "under a minute";
}

function list(names: string[], max = 6): string {
  if (names.length <= max) return names.join(", ");
  return `${names.slice(0, max).join(", ")} and ${names.length - max} more`;
}

/**
 * Decide what the banner says. `null` means the feed status could not be read
 * at all (admin API down, or an apid that predates /v1/feeds).
 *
 * A feed is stale when the server says so: older than staleAfterSeconds, or it
 * has never been confirmed current. A feed whose last attempt failed but whose
 * data is still recent is not stale, but the failure is mentioned.
 */
export function feedBanner(resp: FeedsResponse | null): FeedBanner {
  if (resp === null) {
    return {
      tone: "amber",
      title: "Feed status unavailable",
      detail: "The control plane did not answer /v1/feeds, so the age of the vulnerability data is unknown.",
    };
  }
  if (resp.feeds.length === 0) {
    return {
      tone: "amber",
      title: "Vulnerability feeds have never synced",
      detail:
        "No feed has been loaded. Run `defendsec-feeds sync` (or enable defendsec-feeds.timer); until then matches use only the legacy catalog.",
    };
  }
  const days = Math.round((resp.staleAfterSeconds || STALE_AFTER_SECONDS) / 86400);
  const stale = resp.feeds.filter((f) => f.stale);
  if (stale.length > 0) {
    const never = stale.filter((f) => f.lastSuccess === null).map((f) => f.name);
    const old = stale.filter((f) => f.lastSuccess !== null);
    const parts: string[] = [];
    if (old.length > 0) {
      parts.push(
        old
          .map((f) => `${f.name} (${f.ageSeconds === null ? "age unknown" : describeAge(f.ageSeconds)} old)`)
          .join(", "),
      );
    }
    if (never.length > 0) parts.push(`never synced: ${list(never)}`);
    const errs = stale.filter((f) => f.lastError);
    const why = errs.length > 0 ? ` Last error: ${errs[0].name}: ${errs[0].lastError}` : "";
    return {
      tone: "red",
      title: `${stale.length} of ${resp.feeds.length} vulnerability feeds are older than ${days} days`,
      detail: `${parts.join("; ")}. Findings are being computed against out-of-date data.${why}`,
    };
  }
  const failing = resp.feeds.filter((f) => f.lastError);
  const oldest = resp.oldestAgeSeconds === null ? "" : `, oldest confirmed ${describeAge(resp.oldestAgeSeconds)} ago`;
  const base = `${resp.feeds.length} feed${resp.feeds.length === 1 ? "" : "s"} current${oldest}`;
  if (failing.length > 0) {
    return {
      tone: "amber",
      title: "Vulnerability feeds are current, but the last sync had errors",
      detail: `${base}. Failed on the last attempt: ${list(failing.map((f) => f.name))}.`,
    };
  }
  return { tone: "ok", title: "Vulnerability feeds are current", detail: `${base}.` };
}

// Identity findings in the exposure view (slice 12): the Fleet card, the totals
// of the Fix this week list, and the trend sentence. Pure, imports only the pure
// models, so `node --test` can run it.

import type { ExposureSummary, IdentitySummary, TrendPoint } from "./exposure-model.ts";
import { agoLabel, urgentLabel } from "./surface-exposure.ts";
import { providerLabel } from "./identity-model.ts";

function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export type IdentityCardState = "unavailable" | "not-configured" | "unread" | "read";

export type IdentityCard = {
  state: IdentityCardState;
  tone: "neutral" | "good" | "warning" | "critical";
  /** "Identity (Microsoft 365): 5 findings (1 critical, 2 high), last read 2 hours ago"; "Microsoft 365 and Google Workspace" when both are connected. */
  headline: string;
  /** Anything the headline must not be read without. */
  lines: string[];
};

/**
 * What the Fleet page says about the client's accounts: N findings (x critical,
 * y high), last read <time>. A tenant that was never read is not "clean", and a
 * read that could not assess a check says so, so zero findings is never read as
 * more than it is.
 */
export function identityCard(s: IdentitySummary | undefined, now: number = Date.now()): IdentityCard {
  if (!s) {
    return {
      state: "unavailable",
      tone: "neutral",
      headline: "Identity: unavailable",
      lines: ["The control plane could not be reached, or it is older than the identity API. Nothing here says the accounts are in good order."],
    };
  }
  if (!s.configured) {
    return {
      state: "not-configured",
      tone: "neutral",
      headline: "Identity: no Microsoft 365 tenant or Google Workspace domain connected",
      lines: [
        "Nothing is checked about MFA, administrator roles or mail rules. Connect a read-only app registration (Microsoft 365) or service account (Google Workspace) on the Identity page.",
      ],
    };
  }
  if (!s.lastStatus) {
    return {
      state: "unread",
      tone: "neutral",
      headline: "Identity: not read yet",
      lines: ["The first read runs within a few hours, or start one on the Identity page. No result yet is not a clean result."],
    };
  }
  const lines: string[] = [];
  if (s.lastStatus === "not_assessed") {
    lines.push(`The last read could not assess anything${s.lastReason ? ` (${s.lastReason})` : ""}: missing evidence, not a clean result.`);
  } else if (s.checksNotAssessed > 0) {
    lines.push(`${s.checksNotAssessed} of ${plural(s.checksTotal, "check")} could not run on the latest read: missing evidence, not counted as passing.`);
  } else if (s.lastStatus === "partial") {
    lines.push("Some mailboxes could not be read on the latest read: their rules and filters are not confirmed either way.");
  }
  const urgent = (s.bySeverity.critical ?? 0) + (s.bySeverity.high ?? 0);
  return {
    state: "read",
    tone: urgent > 0 ? "critical" : s.findings > 0 ? "warning" : s.lastStatus !== "ok" ? "neutral" : "good",
    headline: `Identity (${providerNames(s)}): ${plural(s.findings, "finding")} ${urgentLabel(s.bySeverity)}, last read ${agoLabel(s.lastRunAt, now)}`,
    lines,
  };
}

/** "Microsoft 365", "Google Workspace" or both, for the providers the summary covers. */
export function providerNames(s: Pick<IdentitySummary, "provider" | "providers">): string {
  const list = s.providers && s.providers.length > 0 ? s.providers : [s.provider];
  return list.map(providerLabel).join(" and ");
}

/** How many identity findings the Fix this week list has. */
export function identityTotal(f: ExposureSummary["fixable"]): number {
  return f.identity ?? 0;
}

/** One sentence the identity trend's reader can check, or why there is none. */
export function identityTrendSummary(points: TrendPoint[], since?: string | null): string {
  const known = points.filter((p) => p.identityKnown);
  if (known.length === 0) {
    return since ? "No identity read in this window." : "No identity read has run yet: the identity line starts with the first one.";
  }
  const first = known[0];
  const last = known[known.length - 1];
  const a = first.identity ?? 0;
  const b = last.identity ?? 0;
  const delta = b - a;
  const trend = delta === 0 ? "unchanged" : delta < 0 ? `down ${-delta}` : `up ${delta}`;
  return `${plural(b, "open identity finding")} on ${last.day}, ${trend} since ${first.day} (${a}).`;
}

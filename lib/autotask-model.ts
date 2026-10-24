// Autotask tickets (slice 14) as the control plane serves them (GET /v1/autotask/*):
// the wire types and the pure helpers the Autotask page shares. It imports nothing
// from the app, so `node --test` can run it.

export type Urgency = "critical" | "high" | "medium" | "low";

export type AutotaskSettings = {
  mode: "dry_run" | "live";
  apiUser: string;
  zoneUrl: string;
  companyId: number;
  queueId: string;
  status: string;
  source: string;
  issueType: string;
  subIssueType: string;
  priorityCritical: string;
  priorityHigh: string;
  priorityMedium: string;
  noteType: string;
  notePublish: string;
  autoComplete: boolean;
  completeStatus: string;
  minUrgency: "critical" | "high" | "medium";
  dueDaysCritical: number;
  dueDaysHigh: number;
  dueDaysMedium: number;
  consoleUrl: string;
  maxCreates: number;
  updatedBy?: string;
  updatedAt?: string;
};

export type AutotaskCreate = {
  companyID: number;
  title: string;
  description: string;
  status: number;
  priority: number;
  queueID?: number;
  source?: number;
  issueType?: number;
  subIssueType?: number;
  dueDateTime?: string;
};

export type AutotaskOp = {
  kind: "create" | "adopt" | "note" | "complete" | "flag";
  status: "planned" | "done" | "failed" | "deferred" | "skipped";
  groupKey: string;
  tag: string;
  urgency?: Urgency;
  ticketId?: number;
  ticketNumber?: string;
  title: string;
  create?: AutotaskCreate;
  /** Autotask's own names for the picklist values of create (queue, status, priority, source, issueType, subIssueType). */
  labels?: Record<string, string>;
  note?: string;
  reason?: string;
  error?: string;
  members?: number;
};

export type AutotaskRun = {
  id: number;
  mode: "dry_run" | "live";
  triggeredBy: string;
  startedAt: string;
  finishedAt: string;
  status: "ok" | "partial" | "not_run";
  verified: boolean;
  unverifiedWhy: string;
  fingerprint: string;
  companyName: string;
  requests: number;
  groups: number;
  belowThreshold: number;
  created: number;
  noted: number;
  completed: number;
  failed: number;
  deferred: number;
  /** Tickets that need a person's look (closed in Autotask while findings are open, or gone). */
  flagged: number;
  problems: string[];
  ops: AutotaskOp[];
};

export type AutotaskStatus = {
  settings: AutotaskSettings;
  credentials: { configured: boolean; problem?: string; warnings: string[] };
  missing: string[];
  fingerprint: string;
  liveUnlocked: boolean;
  counts: { open: number; resolved: number; closedInPsa: number };
  latestRun: AutotaskRun | null;
  latestDryRun: AutotaskRun | null;
  running: boolean;
  intervalHours: number;
  scheduled: boolean;
  generatedAt: string;
  writeNote: string;
};

export type AutotaskTicket = {
  groupKey: string;
  generation: number;
  tag: string;
  ticketId: number;
  ticketNumber: string;
  title: string;
  state: "open" | "resolved" | "closed_in_psa";
  urgency: Urgency;
  members: number;
  updatedAt: string;
};

export type PickItem = { value: string; label: string; isDefault: boolean; parent?: string };

export type AutotaskPicklists = {
  queues: PickItem[];
  statuses: PickItem[];
  priorities: PickItem[];
  sources: PickItem[];
  issueTypes: PickItem[];
  subIssueTypes: PickItem[];
  noteTypes: PickItem[];
  notePublish: PickItem[];
  titleLength: number;
  descriptionLength: number;
  requests: number;
  company?: { id: number; name: string; active: boolean };
  companyProblem?: string;
};

const OP_KIND: Record<string, string> = {
  create: "New ticket",
  adopt: "Existing ticket (adopted)",
  note: "Note on ticket",
  complete: "Complete ticket",
  flag: "Needs a look",
};

export function opKindLabel(kind: string): string {
  return OP_KIND[kind] ?? kind;
}

export function opStatusLabel(status: string, mode: "dry_run" | "live"): string {
  switch (status) {
    case "planned":
      return mode === "dry_run" ? "would happen" : "planned";
    case "done":
      return "done";
    case "failed":
      return "failed";
    case "deferred":
      return "waits for the next run";
    case "skipped":
      return "not attempted";
  }
  return status;
}

export function runResultLabel(status: string): string {
  switch (status) {
    case "ok":
      return "ok";
    case "partial":
      return "partly done";
    case "not_run":
      return "not run";
  }
  return status;
}

export function stateLabel(state: string): string {
  switch (state) {
    case "open":
      return "open";
    case "resolved":
      return "resolved in DefendSec";
    case "closed_in_psa":
      return "closed in Autotask";
  }
  return state;
}

export function urgencyLabel(u: string): string {
  return u.charAt(0).toUpperCase() + u.slice(1);
}

/** "Security Test Queue (101)", or just the value when the run did not read Autotask's lists. */
export function withLabel(labels: Record<string, string> | undefined, key: string, value: number | undefined, none: string): string {
  if (value === undefined) return none;
  const l = labels?.[key];
  return l ? `${l} (${value})` : String(value);
}

/** The label of a picklist value, or the bare value when the list does not have it. */
export function pickLabel(list: PickItem[] | undefined, value: string): string {
  if (!value) return "not set";
  const hit = list?.find((p) => p.value === value);
  return hit ? hit.label : `${value} (not in Autotask's current list)`;
}

/** The sub-issue types that belong to an issue type. */
export function subIssuesFor(subs: PickItem[], issueType: string): PickItem[] {
  return issueType ? subs.filter((s) => s.parent === issueType) : [];
}

/**
 * What the settings form is still missing before a dry run can show a ticket. It
 * mirrors Settings.Missing in Go and is only for enabling buttons: apid decides.
 */
export function missingChoices(s: Pick<AutotaskSettings, "apiUser" | "companyId" | "queueId" | "status" | "priorityCritical" | "priorityHigh" | "priorityMedium" | "noteType" | "notePublish">): string[] {
  const out: string[] = [];
  if (!s.apiUser.trim()) out.push("the API user's name");
  if (!(s.companyId > 0)) out.push("the Autotask company");
  if (!s.queueId) out.push("the queue");
  if (!s.status) out.push("the status of a new ticket");
  if (!s.priorityCritical || !s.priorityHigh || !s.priorityMedium) out.push("a priority for each of critical, high and medium");
  if (!s.noteType || !s.notePublish) out.push("the note type and who may see a note");
  return out;
}

/**
 * The body of a settings save: every field apid accepts and none it does not (it
 * refuses unknown fields, so the "who saved it and when" the status carries must not
 * be sent back).
 */
export function settingsPayload(s: AutotaskSettings, companyId: number, mode: "dry_run" | "live"): Omit<AutotaskSettings, "updatedBy" | "updatedAt"> {
  const { updatedBy: _by, updatedAt: _at, ...rest } = s;
  void _by;
  void _at;
  return { ...rest, companyId, mode };
}

export function parseCompanyId(text: string): number | null {
  const t = text.trim();
  if (!/^[0-9]{1,15}$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** "3 created, 1 note" style summary of a run's counts. */
export function runSummary(r: Pick<AutotaskRun, "mode" | "created" | "noted" | "completed" | "failed" | "deferred" | "flagged" | "groups" | "belowThreshold">): string {
  const dry = r.mode === "dry_run";
  const parts: string[] = [];
  if (r.created) parts.push(`${r.created} ${dry ? "would be opened" : "opened"}`);
  if (r.noted) parts.push(`${r.noted} ${r.noted === 1 ? "note" : "notes"} ${dry ? "would be added" : "added"}`);
  if (r.completed) parts.push(`${r.completed} ${dry ? "would be completed" : "completed"}`);
  if (r.failed) parts.push(`${r.failed} failed`);
  if (r.deferred) parts.push(`${r.deferred} waiting for the next run`);
  if (r.flagged) parts.push(`${r.flagged} ${r.flagged === 1 ? "ticket needs" : "tickets need"} a look`);
  const head = parts.length ? parts.join(", ") : "nothing to do";
  return `${head} (${r.groups} ${r.groups === 1 ? "action" : "actions"} in Fix this week${r.belowThreshold ? `, ${r.belowThreshold} below the threshold` : ""})`;
}

/** Whether a run's text may be shown as "exact": it read Autotask. */
export function isExact(r: Pick<AutotaskRun, "verified">): boolean {
  return r.verified;
}

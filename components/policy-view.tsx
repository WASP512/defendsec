import { AlertTriangle, ShieldCheck, ShieldX } from "lucide-react";

import type {
  BreakGlassStatus,
  PendingCommand,
  PolicyDecision,
  PolicyStatus,
} from "@/lib/response-policy";

// Policy-governed response (roadmap 2.1-2.6).
//
// What this page is for: making the rules legible before an incident, and
// making refusals understandable during one. A refusal that says only
// "forbidden" produces a support ticket and then a request for a bypass; one
// that names the rule produces a conversation about the rule.

export function BreakGlassBanner({
  status,
}: {
  status: BreakGlassStatus | null;
}) {
  const active = status?.active;
  if (!active) return null;

  // Deliberately not dismissible. A bypass that can be hidden is one people
  // forget is open.
  return (
    <section className="rounded-xl border-2 border-destructive bg-destructive/10 p-5">
      <div className="flex items-center gap-2">
        <AlertTriangle className="size-5 text-destructive" aria-hidden />
        <h2 className="text-sm font-semibold text-destructive">
          Break-glass is open — policy limits are bypassed
        </h2>
      </div>
      <p className="mt-2 text-sm">{active.justification}</p>
      <p className="mt-2 text-xs text-muted-foreground">
        Opened by {active.openedBy} · expires{" "}
        {new Date(active.expiresAt)
          .toISOString()
          .replace("T", " ")
          .slice(0, 16)}{" "}
        UTC. Explicit deny rules and two-person requirements still apply.
      </p>
    </section>
  );
}

export function PolicySummary({ status }: { status: PolicyStatus }) {
  if (!status.loaded) {
    return (
      <section className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-5">
        <div className="flex items-center gap-2">
          <ShieldX
            className="size-4 text-amber-600 dark:text-amber-400"
            aria-hidden
          />
          <h2 className="text-sm font-medium">No policy loaded</h2>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">{status.detail}</p>
      </section>
    );
  }

  return (
    <section className="rounded-xl border bg-background p-5">
      <div className="flex items-center gap-2">
        <ShieldCheck className="size-4 text-emerald-500" aria-hidden />
        <h2 className="text-sm font-medium">{status.name}</h2>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">{status.detail}</p>
      <dl className="mt-4 grid gap-3 sm:grid-cols-3 text-xs">
        <div>
          <dt className="text-muted-foreground">Rules</dt>
          <dd className="text-sm">{status.rules?.length ?? 0}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Blast-radius limits</dt>
          <dd className="text-sm">{status.limits?.length ?? 0}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Document</dt>
          <dd className="truncate font-mono text-sm" title={status.hash}>
            {status.hash?.slice(0, 16)}
          </dd>
        </div>
      </dl>

      {status.rules && status.rules.length > 0 ? (
        <ul className="mt-4 space-y-2 border-t pt-4 text-xs">
          {status.rules.map((rule) => (
            <li key={rule.id} className="flex gap-2">
              <span
                className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[11px] ${
                  rule.effect === "deny"
                    ? "bg-destructive/15 text-destructive"
                    : "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                }`}
              >
                {rule.effect}
              </span>
              <span className="text-muted-foreground">
                <code className="text-foreground">{rule.id}</code> —{" "}
                {rule.commands.join(", ")}
                {rule.host_classes?.length
                  ? ` on ${rule.host_classes.join("/")}`
                  : null}
                {rule.exclude_host_classes?.length
                  ? ` except ${rule.exclude_host_classes.join("/")}`
                  : null}
                {rule.require_approvals && rule.require_approvals > 1
                  ? ` · needs ${rule.require_approvals} approvals`
                  : null}
                {rule.reason ? ` · ${rule.reason}` : null}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {status.limits && status.limits.length > 0 ? (
        <ul className="mt-4 space-y-1 border-t pt-4 text-xs text-muted-foreground">
          {status.limits.map((l) => (
            <li key={l.id}>
              <code className="text-foreground">{l.id}</code> — at most {l.max}{" "}
              {l.commands.join("/")}{" "}
              {l.scope === "fleet" ? "fleet-wide" : "per host"} per {l.per}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

export function PendingApprovals({ pending }: { pending: PendingCommand[] }) {
  if (pending.length === 0) return null;

  return (
    <section className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-5">
      <h2 className="text-sm font-medium">
        Waiting for a second approver ({pending.length})
      </h2>
      <p className="mt-1 text-xs text-muted-foreground">
        These commands are <span className="text-foreground">not signed</span>{" "}
        and will not run until another administrator approves them.
      </p>
      <ul className="mt-3 space-y-3">
        {pending.map((p) => (
          <li
            key={p.id}
            className="border-t pt-3 text-sm first:border-t-0 first:pt-0"
          >
            <div className="flex flex-wrap items-baseline gap-x-2">
              <code className="text-xs">{p.commandType}</code>
              <span className="text-muted-foreground">
                on {p.hostname || p.deviceId}
              </span>
              <span className="text-xs text-muted-foreground">
                {p.approvals.length} of {p.requiredApprovals} approvals
              </span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Requested by {p.requestedBy}
              {p.ruleId ? ` under rule ${p.ruleId}` : null} · expires{" "}
              {new Date(p.expiresAt)
                .toISOString()
                .replace("T", " ")
                .slice(11, 16)}{" "}
              UTC
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function RecentDecisions({
  decisions,
}: {
  decisions: PolicyDecision[];
}) {
  return (
    <section className="rounded-xl border bg-background p-5">
      <h2 className="text-sm font-medium">Recent decisions</h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Refusals are recorded as well as permissions. &ldquo;Did anyone
        try&rdquo; is the question asked after an incident, and only a
        deny-by-default engine can answer it.
      </p>
      {decisions.length === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">
          No decisions recorded yet.
        </p>
      ) : (
        <ul className="mt-3 space-y-2 text-xs">
          {decisions.slice(0, 40).map((d) => (
            <li
              key={d.id}
              className="flex gap-2 border-t pt-2 first:border-t-0 first:pt-0"
            >
              <span
                className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[11px] ${
                  d.effect === "deny"
                    ? "bg-destructive/15 text-destructive"
                    : d.effect === "require-approval"
                      ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                      : "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                }`}
              >
                {d.effect}
              </span>
              <span className="text-muted-foreground">
                <code className="text-foreground">{d.commandType}</code>
                {d.hostname ? ` on ${d.hostname}` : null} · {d.actor}
                {d.breakGlassId ? " · via break-glass" : null}
                <br />
                {d.reason}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

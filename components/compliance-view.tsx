import Link from "next/link";

import {
  STATUS_HINT,
  STATUS_LABEL,
  STATUS_ORDER,
  type Assessment,
  type ControlStatus,
  type ControlStatusValue,
  type FrameworkSummary,
} from "@/lib/compliance";

// The compliance view (roadmap 1.9).
//
// Two rules shape this page. Deficiencies and gaps come first, because a
// reader who stops after the first screen should have seen what needs
// attention. And there is no overall score: a percentage is where a control
// nobody has looked at disappears into a rounding error, so the counts are
// shown per status and the controls are listed by name.

const STATUS_TONE: Record<ControlStatusValue, string> = {
  deficient: "border-destructive/40 bg-destructive/10 text-destructive",
  excepted:
    "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  "no-evidence":
    "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  "not-evidenced": "border-border bg-muted text-muted-foreground",
  satisfied:
    "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
};

export function FrameworkPicker({
  frameworks,
  active,
  periodId,
}: {
  frameworks: FrameworkSummary[];
  active: string;
  periodId?: string;
}) {
  return (
    <nav className="flex flex-wrap gap-2">
      {frameworks.map((f) => {
        const params = new URLSearchParams({ framework: f.id });
        if (periodId) params.set("periodId", periodId);
        const isActive = f.id === active;
        return (
          <Link
            key={f.id}
            href={`/compliance?${params.toString()}`}
            className={`rounded-md border px-3 py-1.5 text-sm ${
              isActive ? "bg-foreground text-background" : "hover:bg-muted"
            }`}
          >
            {f.title}
            <span
              className={`ml-2 text-xs ${isActive ? "opacity-70" : "text-muted-foreground"}`}
            >
              {f.total}
            </span>
          </Link>
        );
      })}
    </nav>
  );
}

function ControlRow({ cs }: { cs: ControlStatus }) {
  return (
    <li className="space-y-1 border-t py-3 first:border-t-0">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <code className="text-xs text-muted-foreground">{cs.control.id}</code>
        <span className="text-sm font-medium">{cs.control.title}</span>
        {cs.qualified && cs.status === "satisfied" ? (
          <span className="rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[11px] text-amber-600 dark:text-amber-400">
            partial coverage
          </span>
        ) : null}
      </div>
      <p className="text-sm text-muted-foreground">{cs.statement}</p>
      {cs.exceptions && cs.exceptions.length > 0 ? (
        <ul className="mt-1 space-y-1 border-l-2 border-amber-500/40 pl-3 text-xs text-muted-foreground">
          {cs.exceptions.map((e) => (
            <li key={e.id}>
              <span className="text-foreground">{e.reason}</span>
              {e.owner ? ` — owner ${e.owner}` : null}
              {e.remediation ? ` — ${e.remediation}` : null}
              {" — expires "}
              {new Date(e.expiresAt).toISOString().slice(0, 10)}
              {e.closedAt ? " (closed)" : null}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function ComplianceView({ assessment }: { assessment: Assessment }) {
  const byStatus = new Map<ControlStatusValue, ControlStatus[]>();
  for (const cs of assessment.controls) {
    const list = byStatus.get(cs.status) ?? [];
    list.push(cs);
    byStatus.set(cs.status, list);
  }

  const from = new Date(assessment.period.startsAt).toISOString().slice(0, 10);
  const to = new Date(assessment.period.endsAt).toISOString().slice(0, 10);

  return (
    <div className="space-y-6">
      <section className="rounded-xl border bg-background p-5">
        <h2 className="text-sm font-medium">{assessment.title}</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          {assessment.period.name} · {from} to {to}
          {assessment.period.closedAt ? " · period closed" : null}
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          {STATUS_ORDER.map((status) => {
            const n = assessment.counts[status] ?? 0;
            if (n === 0) return null;
            return (
              <span
                key={status}
                className={`rounded-md border px-2.5 py-1 text-xs ${STATUS_TONE[status]}`}
                title={STATUS_HINT[status]}
              >
                {STATUS_LABEL[status]}: {n}
              </span>
            );
          })}
        </div>
      </section>

      {STATUS_ORDER.map((status) => {
        const group = byStatus.get(status) ?? [];
        if (group.length === 0) return null;
        return (
          <section key={status} className="rounded-xl border bg-background p-5">
            <div className="flex items-baseline justify-between gap-3">
              <h3 className="text-sm font-medium">
                {STATUS_LABEL[status]}{" "}
                <span className="text-muted-foreground">({group.length})</span>
              </h3>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {STATUS_HINT[status]}
            </p>
            <ul className="mt-3">
              {group.map((cs) => (
                <ControlRow key={cs.control.id} cs={cs} />
              ))}
            </ul>
          </section>
        );
      })}

      <section className="rounded-xl border border-amber-500/40 bg-amber-500/5 p-5">
        <h3 className="text-sm font-medium">
          Read this before relying on any of the above
        </h3>
        <ul className="mt-2 space-y-2 text-sm text-muted-foreground">
          {assessment.caveats.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

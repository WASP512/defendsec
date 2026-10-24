import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { WhyRanksHere } from "@/components/exposure-list";
import { ageLabel, type ExposureGroup } from "@/lib/exposure-model";
import { checkLabel, providerLabel, type ExposureIdentityResponse } from "@/lib/identity-model";
import { intervalLines, observationText } from "@/lib/surface-exposure";

/**
 * The drawer of an identity finding: what was found, how to fix it, the evidence
 * behind it (a rule's name, conditions and actions, or the registration flags: the
 * definition, never a message), how long it has been open, and what the latest read
 * said of its check. It never claims more than the read saw: a check that could not
 * run says so.
 */
export function IdentityExposureDetail({ group, response }: { group: ExposureGroup | null; response: ExposureIdentityResponse }) {
  const { detail } = response;
  const f = detail.finding;
  const resolved = response.status === "resolved";
  const subject = {
    advisoryId: response.advisoryId,
    source: "identity" as const,
    severity: f.severity,
    kev: false,
    kevAdded: null,
    epss: null,
    cvss: null,
  };
  const state = detail.checkState;
  const unconfirmed = !resolved && (f.unconfirmed || (state !== null && !state.assessed));
  return (
    <div className="space-y-5" data-identity-detail={response.advisoryId}>
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={subject.severity} />
          <Badge variant="outline">{providerLabel(f.provider)}</Badge>
          <Badge variant="outline">{resolved ? "resolved" : "open"}</Badge>
        </div>
        <WhyRanksHere group={subject} />
        <p className="text-sm font-medium">{f.title}</p>
        {f.detail ? <p className="text-sm">{f.detail}</p> : null}
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">Account or rule</dt>
          <dd>{f.subjectLabel}</dd>
          <dt className="text-muted-foreground">Check</dt>
          <dd>
            {checkLabel(f.check, f.provider)} · <code>{f.findingId}</code>
          </dd>
          {f.controls.length > 0 ? (
            <>
              <dt className="text-muted-foreground">Controls</dt>
              <dd>{f.controls.join(", ")}</dd>
            </>
          ) : null}
          <dt className="text-muted-foreground">Last confirmed</dt>
          <dd>{f.lastSeen.slice(0, 16).replace("T", " ")} UTC</dd>
        </dl>
      </section>

      {f.fix && !resolved ? (
        <section className="space-y-1">
          <h3 className="text-sm font-medium">How to fix it</h3>
          <p className="text-sm" data-fix-text>
            {f.fix}
          </p>
        </section>
      ) : null}

      <section className="space-y-1">
        <h3 className="text-sm font-medium">Open on, closed on</h3>
        <p className="text-xs text-muted-foreground">{ageLabel(f.firstSeen, f.resolvedAt)}</p>
        <ul className="space-y-0.5 text-sm" data-intervals>
          {intervalLines(detail.intervals).map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </section>

      {unconfirmed ? (
        <p
          role="status"
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-200"
          data-unconfirmed
        >
          The latest read could not cover this: {state && !state.assessed ? `${checkLabel(f.check, f.provider)} was not assessed (${state.reason || "no reason recorded"})` : "its mailbox could not be read"}.
          This finding is shown from its last confirmation, not from today.
        </p>
      ) : null}

      <section className="space-y-2">
        <h3 className="text-sm font-medium">What the read saw</h3>
        <p className="text-xs text-muted-foreground">
          Account and rule definitions only. DefendSec does not read messages, so no sender, subject or body of any mail is here.
        </p>
        <pre className="max-h-80 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs" data-evidence>
          {observationText(f.evidence)}
        </pre>
      </section>

      <p className="text-xs text-muted-foreground">
        {group?.identity ? `${providerLabel(group.identity.provider)} · ${checkLabel(group.identity.check, group.identity.provider)}` : checkLabel(f.check, f.provider)}. This is evidence of how the
        tenant is configured, not proof that anyone has abused it.{" "}
        <Link href={f.provider === "google" ? "/identity/google" : "/identity"} className="underline">
          All identity findings
        </Link>
      </p>
    </div>
  );
}

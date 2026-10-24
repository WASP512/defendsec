import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { WhyRanksHere } from "@/components/exposure-list";
import { ageLabel, type ExposureGroup } from "@/lib/exposure-model";
import { checkLabel, kindLabel } from "@/lib/surface-model";
import {
  intervalLines,
  observationText,
  surfaceWhere,
  type ExposureSurfaceResponse,
} from "@/lib/surface-exposure";

/**
 * The drawer of an external surface finding: what was found, how to fix it, the
 * raw observation behind it (the record text or certificate fields, so it can
 * be checked with dig or openssl), how long it has been open, and what the
 * latest check said. It never claims more than the scan saw: a check that
 * could not run says so.
 */
export function SurfaceExposureDetail({ group, response }: { group: ExposureGroup | null; response: ExposureSurfaceResponse }) {
  const { detail } = response;
  const f = detail.finding;
  const resolved = response.status === "resolved";
  const subject = {
    advisoryId: response.advisoryId,
    source: "surface" as const,
    severity: f.severity === "info" ? ("low" as const) : f.severity,
    kev: false,
    kevAdded: null,
    epss: null,
    cvss: null,
  };
  const evidenceKeys = Object.keys(f.evidence ?? {});
  return (
    <div className="space-y-5" data-surface-detail={response.advisoryId}>
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={subject.severity} />
          <Badge variant="outline">external surface</Badge>
          <Badge variant="outline">{resolved ? "resolved" : "open"}</Badge>
        </div>
        {f.severity === "info" ? (
          <p className="text-sm" data-rank-reason>
            <span className="font-medium">Informational</span>
            <span className="text-muted-foreground"> · a note about the asset, never counted as a finding and never ranked</span>
          </p>
        ) : (
          <WhyRanksHere group={subject} />
        )}
        <p className="text-sm font-medium">{f.title}</p>
        {f.detail ? <p className="text-sm">{f.detail}</p> : null}
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">{kindLabel(f.assetKind)}</dt>
          <dd>{f.assetValue}</dd>
          <dt className="text-muted-foreground">Check</dt>
          <dd>
            {checkLabel(f.check)} · <code>{f.findingId}</code>
            {f.subject && f.subject !== f.assetValue ? <> · {f.subject}</> : null}
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

      {detail.unconfirmed && detail.latest ? (
        <p
          role="status"
          className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-200"
          data-unconfirmed
        >
          The latest {checkLabel(f.check)} check could not run ({detail.latest.reason || "no reason recorded"}, scan {detail.latest.scanId}). This
          finding is shown from its last confirmation, not from today.
        </p>
      ) : null}

      <section className="space-y-2">
        <h3 className="text-sm font-medium">What the scan saw</h3>
        {detail.confirmed ? (
          <>
            <p className="text-xs text-muted-foreground">
              Scan {detail.confirmed.scanId} at {detail.confirmed.observedAt.slice(0, 16).replace("T", " ")} UTC
              {detail.confirmed.assessed ? "" : ` · not assessed: ${detail.confirmed.reason}`}
            </p>
            <pre className="max-h-72 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs" data-observation>
              {observationText(detail.confirmed.observed)}
            </pre>
          </>
        ) : (
          <p className="text-sm text-muted-foreground">No observation is stored for this finding.</p>
        )}
        {evidenceKeys.length > 0 ? (
          <details className="text-sm">
            <summary className="cursor-pointer text-muted-foreground">Evidence recorded with the finding</summary>
            <pre className="mt-1 max-h-60 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs">{observationText(f.evidence)}</pre>
          </details>
        ) : null}
      </section>

      <p className="text-xs text-muted-foreground">
        {group ? surfaceWhere(group) : `${f.assetValue} · ${checkLabel(f.check)}`}. This is evidence that something is reachable or
        configured a certain way, not proof that anyone has used it. The signed evidence export carries this scan and its raw
        observations.{" "}
        <Link href="/surface" className="underline">
          All surface findings
        </Link>
      </p>
    </div>
  );
}

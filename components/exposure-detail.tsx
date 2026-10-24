import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { FindingActions } from "@/components/finding-actions";
import { WhyRanksHere } from "@/components/exposure-list";
import { feedLabel } from "@/lib/findings-model";
import {
  ageLabel,
  hostStatus,
  resolutionLabel,
  watchLabel,
  type ExposureAdvisoryResponse,
  type ExposureGroup,
} from "@/lib/exposure-model";
import type { FindingTriage } from "@/lib/types";

/**
 * The provenance drawer's content: the advisory, every affected host with
 * installed against fixed version, how long each has been open (or how it
 * closed), and the feed snapshots the findings were computed from.
 */
export function ExposureDetail({
  group,
  detail,
  triages,
  readOnly,
}: {
  group: ExposureGroup | null;
  detail: ExposureAdvisoryResponse;
  triages: FindingTriage[];
  readOnly: boolean;
}) {
  const adv = detail.advisory;
  const subject = {
    advisoryId: detail.advisoryId,
    severity: adv?.severity ?? group?.severity ?? "unknown",
    kev: adv?.kev ?? group?.kev ?? false,
    kevAdded: adv?.kevAdded ?? group?.kevAdded ?? null,
    epss: adv?.epss ?? group?.epss ?? null,
    cvss: adv?.cvssScore ?? group?.cvss ?? null,
  } as const;
  const resolved = detail.status === "resolved";
  const kinds = [...new Set(detail.hosts.map((h) => h.kind))];
  const awaitingSince = detail.hosts.map((h) => h.upstreamFixedOn).filter(Boolean).sort().pop() ?? null;

  return (
    <div className="space-y-5" data-exposure-detail={detail.advisoryId}>
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={subject.severity} />
          {subject.kev ? <Badge variant="destructive">CISA KEV</Badge> : null}
          <Badge variant="outline">{resolved ? "resolved" : "open"}</Badge>
          {detail.bucket === "watch" ? <Badge variant="outline">{watchLabel({ kinds, awaitingSince })}</Badge> : null}
        </div>
        <WhyRanksHere group={subject} />
        {adv?.summary ? <p className="text-sm">{adv.summary}</p> : null}
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted-foreground">Advisory</dt>
          <dd>{detail.advisoryId}</dd>
          {adv?.kevAdded ? (
            <>
              <dt className="text-muted-foreground">On KEV since</dt>
              <dd>{adv.kevAdded}</dd>
            </>
          ) : null}
          {adv?.epss !== null && adv?.epss !== undefined ? (
            <>
              <dt className="text-muted-foreground">EPSS</dt>
              <dd>
                {adv.epss.toFixed(2)} ({(adv.epss * 100).toFixed(adv.epss < 0.1 ? 1 : 0)}% chance of exploitation in the
                next 30 days{adv.epssDate ? `, scored ${adv.epssDate}` : ""})
              </dd>
            </>
          ) : null}
          {adv?.cvssScore !== null && adv?.cvssScore !== undefined ? (
            <>
              <dt className="text-muted-foreground">CVSS</dt>
              <dd>
                {adv.cvssScore.toFixed(1)}
                {adv.cvssVector ? <span className="text-muted-foreground"> · {adv.cvssVector}</span> : null}
              </dd>
            </>
          ) : null}
          {adv?.cwe?.length ? (
            <>
              <dt className="text-muted-foreground">Weakness</dt>
              <dd>{adv.cwe.join(", ")}</dd>
            </>
          ) : null}
        </dl>
        {!adv ? (
          <p className="text-sm text-muted-foreground">
            The advisory record is no longer in the database (a feed re-sync removed it); the findings below keep what
            they matched.
          </p>
        ) : null}
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-medium">
          {detail.hosts.length} affected host finding{detail.hosts.length === 1 ? "" : "s"}
          {detail.truncated ? " (first 500)" : ""}
        </h3>
        <ul className="space-y-2">
          {detail.hosts.map((h) => {
            const status = hostStatus(h, triages);
            const resolution = resolutionLabel(h);
            return (
              <li key={h.findingId} className="space-y-1 rounded-lg border p-3" data-host-finding={h.findingId}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link href={`/devices/${h.deviceId}`} className="font-medium underline">
                      {h.hostname || h.deviceId}
                    </Link>
                    <Badge variant="outline" data-status={status}>
                      {status}
                    </Badge>
                    {h.kind === "awaiting_vendor" ? <Badge variant="outline">awaiting vendor</Badge> : null}
                    {h.kind === "unfixed" ? <Badge variant="outline">no fix published</Badge> : null}
                  </div>
                  {!readOnly && status !== "resolved" ? (
                    <FindingActions findingKey={h.key} status={status === "acknowledged" ? "acknowledged" : "open"} />
                  ) : null}
                </div>
                <p className="text-sm">
                  {h.package}: installed <code>{h.installed}</code>
                  {h.fixed ? (
                    <>
                      {" "}
                      · fixed in <code>{h.fixed.replace(/^0:/, "")}</code>
                    </>
                  ) : (
                    " · no fixed version"
                  )}
                </p>
                {h.kind === "awaiting_vendor" && h.reason ? (
                  <p className="text-sm text-muted-foreground">{h.reason}</p>
                ) : null}
                <p className="text-xs text-muted-foreground">{ageLabel(h.firstSeen, h.resolvedAt)}</p>
                {resolution ? <p className="text-sm" data-resolution={h.resolution || "unrecorded"}>{resolution}</p> : null}
                <p className="text-xs text-muted-foreground">
                  {feedLabel(h)}
                  {h.snapshotId !== null ? ` · snapshot ${h.snapshotId}` : ""}
                  {h.rangeId !== null ? ` · range ${h.rangeId}` : ""}
                  {" · "}
                  <Link href={`/findings/${h.findingId}`} className="underline">
                    finding {h.findingId}
                  </Link>
                </p>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-medium">Feed snapshots these findings came from</h3>
        {detail.snapshots.length === 0 ? (
          <p className="text-sm text-muted-foreground">No snapshot is recorded for these findings.</p>
        ) : (
          detail.snapshots.map((s) => (
            <div key={s.id} className="rounded-lg border p-3 text-sm" data-snapshot={s.id}>
              <p className="font-medium">
                Snapshot {s.id}
                <span className="font-normal text-muted-foreground"> · recorded {s.createdAt.slice(0, 16).replace("T", " ")} UTC</span>
              </p>
              <ul className="mt-1 space-y-0.5 text-xs text-muted-foreground">
                {s.feeds.map((f) => (
                  <li key={f.name}>
                    {f.name}: fetched {f.fetchedAt.slice(0, 10)} · {f.recordCount} records · sha256{" "}
                    <code>{f.sha256.slice(0, 12)}…</code>
                  </li>
                ))}
              </ul>
            </div>
          ))
        )}
      </section>
    </div>
  );
}

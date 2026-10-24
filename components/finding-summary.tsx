import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/status-badge";
import { cn } from "@/lib/utils";
import {
  eolStageLabel,
  feedLabel,
  fixLabel,
  originLabel,
  type CoverageNotice,
  type ExploitedNotice,
  type VulnFinding,
} from "@/lib/findings-model";
import type { FindingStatus } from "@/lib/types";

/** One finding: what, where, what fixes it, and what data it came from. */
export function FindingSummary({
  finding,
  status,
  showHost = false,
}: {
  finding: VulnFinding;
  status: FindingStatus;
  showHost?: boolean;
}) {
  return (
    <div className="space-y-1" data-finding-kind={finding.kind}>
      <div className="flex flex-wrap items-center gap-2">
        <Link href={`/findings/${finding.id}`} className="font-medium underline-offset-2 hover:underline">
          {finding.cve || finding.advisoryId}
        </Link>
        <SeverityBadge severity={finding.severity} />
        {finding.kev ? <Badge variant="destructive">KEV</Badge> : null}
        {finding.epss !== null ? (
          <Badge variant="outline" title="EPSS: probability of exploitation in the next 30 days">
            EPSS {(finding.epss * 100).toFixed(finding.epss < 0.1 ? 1 : 0)}%
          </Badge>
        ) : null}
        {finding.kind === "awaiting_vendor" ? (
          <Badge variant="outline" title="Fixed upstream by Red Hat; your distribution has not released it yet">
            awaiting vendor
          </Badge>
        ) : null}
        {finding.kind === "eol" && finding.eol ? <Badge variant="outline">{eolStageLabel(finding.eol)}</Badge> : null}
        {finding.kind === "unfixed" ? <Badge variant="outline">no fix published</Badge> : null}
        {finding.kind === "informational" ? <Badge variant="outline">informational</Badge> : null}
        {status === "acknowledged" ? <Badge variant="outline">acknowledged</Badge> : null}
      </div>
      <p className="text-sm">
        {finding.package} {finding.installed}
        {showHost && finding.hostname ? (
          <>
            {" "}
            on{" "}
            <Link href={`/devices/${finding.deviceId}`} className="underline">
              {finding.hostname}
            </Link>
          </>
        ) : null}
        {" — "}
        {fixLabel(finding)}
      </p>
      {finding.kind === "awaiting_vendor" && finding.reason ? (
        <p className="text-sm text-muted-foreground" data-awaiting-reason>
          {finding.reason}
        </p>
      ) : null}
      {finding.kind === "eol" && finding.eol ? (
        <p className="text-sm text-muted-foreground" data-eol-origin>
          Installed from {originLabel(finding)}, not the distribution
          {finding.eol.packages.length > 0 ? ` · ${finding.eol.packages.join(", ")}` : ""}
        </p>
      ) : null}
      {finding.summary ? <p className="text-sm text-muted-foreground">{finding.summary}</p> : null}
      <p className="text-xs text-muted-foreground">
        {feedLabel(finding)} · advisory {finding.advisoryId}
        {finding.rangeId !== null ? ` · range ${finding.rangeId}` : ""}
        {finding.snapshotId !== null ? ` · snapshot ${finding.snapshotId}` : ""}
      </p>
    </div>
  );
}

/** Amber notice: this host's empty list does not mean "patched". */
export function CoverageBanner({ notice }: { notice: CoverageNotice }) {
  return (
    <div
      role="status"
      data-coverage-notice
      className={cn(
        "flex items-start gap-3 rounded-lg border px-4 py-3 text-sm",
        "border-amber-500/40 bg-amber-500/10 text-amber-900 dark:text-amber-200",
      )}
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="space-y-0.5">
        <p className="font-medium">{notice.title}</p>
        <p className="opacity-90">{notice.detail}</p>
      </div>
    </div>
  );
}

/** Red notice: exploited in the wild, fixed upstream, not yet released here. */
export function ExploitedAwaitingBanner({ notice }: { notice: ExploitedNotice }) {
  return (
    <div
      role="alert"
      data-exploited-awaiting
      className={cn(
        "flex items-start gap-3 rounded-lg border px-4 py-3 text-sm",
        "border-red-500/50 bg-red-500/10 text-red-900 dark:text-red-200",
      )}
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="space-y-0.5">
        <p className="font-medium">{notice.title}</p>
        <p className="opacity-90">{notice.detail}</p>
      </div>
    </div>
  );
}

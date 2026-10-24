import { Badge } from "@/components/ui/badge";
import {
  assetStanding,
  checkLabel,
  kindLabel,
  severityCounts,
  type AssetGroup,
  type SurfaceFinding,
  type SurfaceSeverity,
} from "@/lib/surface-model";

function SeverityPill({ severity }: { severity: SurfaceSeverity }) {
  if (severity === "critical" || severity === "high") return <Badge variant="destructive">{severity}</Badge>;
  if (severity === "medium") return <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400">medium</Badge>;
  if (severity === "low") return <Badge variant="secondary">low</Badge>;
  return <Badge variant="outline">info</Badge>;
}

function day(iso: string) {
  return new Date(iso).toLocaleDateString();
}

function Evidence({ value }: { value: Record<string, unknown> }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(value, null, 2)}</pre>
  );
}

function FindingRow({ finding, resolved }: { finding: SurfaceFinding; resolved?: boolean }) {
  return (
    <details className="group rounded-lg border bg-background">
      <summary className="flex cursor-pointer flex-wrap items-center gap-2 p-3">
        <SeverityPill severity={finding.severity} />
        <span className="font-medium">{finding.title}</span>
        <span className="text-xs text-muted-foreground">
          {checkLabel(finding.check)}
          {finding.subject && finding.subject !== finding.assetValue ? ` · ${finding.subject}` : ""}
        </span>
        <span className="ml-auto text-xs text-muted-foreground">
          {resolved && finding.resolvedAt
            ? `open ${day(finding.firstSeen)} to ${day(finding.resolvedAt)}`
            : `first seen ${day(finding.firstSeen)}`}
        </span>
      </summary>
      <div className="space-y-3 border-t p-3 text-sm">
        <p>{finding.detail}</p>
        {finding.fix ? (
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">How to fix it</div>
            <p>{finding.fix}</p>
          </div>
        ) : null}
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Evidence</div>
          <Evidence value={finding.evidence} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {finding.controls.map((c) => (
            <Badge key={c} variant="outline">
              {c}
            </Badge>
          ))}
          <span className="ml-auto text-xs text-muted-foreground">last confirmed {day(finding.lastSeen)}</span>
        </div>
      </div>
    </details>
  );
}

export function SurfaceAssetCard({ group }: { group: AssetGroup }) {
  const { asset } = group;
  const standing = assetStanding(asset);
  const counts = severityCounts(group.findings);
  const tone =
    standing.kind === "findings"
      ? "text-foreground"
      : standing.kind === "clean"
        ? "text-emerald-700 dark:text-emerald-400"
        : "text-muted-foreground";
  return (
    <section className="space-y-3 rounded-xl border bg-card p-4">
      <header className="space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-medium break-all">{asset.value}</h2>
          <Badge variant="outline">{kindLabel(asset.kind)}</Badge>
          {counts.map((c) => (
            <span key={c.severity} className="flex items-center gap-1 text-xs">
              <SeverityPill severity={c.severity} /> {c.count}
            </span>
          ))}
        </div>
        <p className={`text-sm ${tone}`}>{standing.text}</p>
        {asset.lastScanAt ? (
          <p className="text-xs text-muted-foreground">Last scan {new Date(asset.lastScanAt).toLocaleString()}.</p>
        ) : null}
      </header>

      {asset.notAssessed.length > 0 ? (
        <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <div className="font-medium">Could not be assessed</div>
          <p className="text-muted-foreground">
            These checks did not reach a conclusion. That is missing evidence, not a clean result.
          </p>
          <ul className="mt-2 space-y-1">
            {asset.notAssessed.map((c) => (
              <li key={c.check}>
                <span className="font-medium">{checkLabel(c.check)}</span>: {c.reason || "no reason recorded"}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {group.findings.length > 0 ? (
        <div className="space-y-2">
          {group.findings.map((f) => (
            <FindingRow key={f.id} finding={f} />
          ))}
        </div>
      ) : null}

      {group.resolved.length > 0 ? (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted-foreground">Closed findings ({group.resolved.length})</summary>
          <div className="mt-2 space-y-2">
            {group.resolved.map((f) => (
              <FindingRow key={f.id} finding={f} resolved />
            ))}
          </div>
        </details>
      ) : null}
    </section>
  );
}

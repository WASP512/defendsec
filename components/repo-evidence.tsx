import { Badge } from "@/components/ui/badge";
import { AlertTriangle } from "lucide-react";
import type { RepoDetail } from "@/lib/findings-model";
import {
  repoCodeLabel,
  unreliableExplanation,
  unreliableTitle,
  type PatchReliability,
  type RepoEvidence as RepoEvidenceRow,
  type RepoHealthReport,
} from "@/lib/patch-reliability";

function day(iso?: string): string {
  return iso ? iso.slice(0, 10) : "";
}

/**
 * The evidence behind a repository-health finding: every problem found, the
 * dates the verdict rests on, and how to fix it. Read-only facts the agent
 * collected; nothing here was fetched or refreshed.
 */
export function RepoEvidence({ repo, controls }: { repo: RepoDetail; controls?: string[] }) {
  const dates: string[] = [];
  if (repo.releaseDate) dates.push(`Release file dated ${day(repo.releaseDate)}`);
  if (repo.validUntil) dates.push(`valid until ${day(repo.validUntil)}`);
  if (repo.metadataTime) dates.push(`metadata cached ${day(repo.metadataTime)}`);
  if (repo.keyExpires) dates.push(`key expires ${day(repo.keyExpires)}`);
  if (repo.lastRefresh) dates.push(`host last refreshed ${day(repo.lastRefresh)} (${repo.lastRefreshSource ?? "unknown source"})`);
  return (
    <div className="space-y-1 text-sm" data-repo-evidence>
      <p>
        <span className="font-medium">{repo.label}</span>
        <span className="text-muted-foreground">
          {" "}
          · {repo.manager}
          {repo.keyId ? ` · key ${repo.keyId}` : ""}
          {repo.signedBy ? ` · ${repo.signedBy}` : ""}
          {repo.source ? ` · ${repo.source}` : ""}
        </span>
      </p>
      <ul className="list-disc space-y-0.5 pl-5">
        {repo.problems.map((p) => (
          <li key={p.code} data-repo-problem={p.code}>
            <span className="font-medium">{repoCodeLabel(p.code)}</span>
            <span className="text-muted-foreground"> ({p.severity}): {p.detail}</span>
          </li>
        ))}
      </ul>
      {dates.length > 0 ? <p className="text-xs text-muted-foreground">{dates.join(" · ")} · stale after {repo.staleAfterDays} days</p> : null}
      {repo.fix ? (
        <p data-repo-fix>
          <span className="font-medium">Fix: </span>
          {repo.fix}
        </p>
      ) : null}
      {controls?.length ? <p className="text-muted-foreground">Evidence for: {controls.join(", ")}</p> : null}
    </div>
  );
}

/**
 * Shown wherever a host's pending updates appear, when they cannot be
 * believed: the count is what the package manager can see, and the reasons say
 * why that may be less than what is available.
 */
export function PatchReliabilityNotice({ reliability }: { reliability: PatchReliability }) {
  if (reliability.state !== "unreliable") return null;
  return (
    <div
      role="alert"
      data-patch-unreliable
      className="flex items-start gap-3 rounded-lg border border-amber-500/50 bg-amber-500/10 px-4 py-3 text-sm text-amber-900 dark:text-amber-200"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 space-y-1">
        <p className="font-medium">{unreliableTitle()}</p>
        <p className="opacity-90">{unreliableExplanation()}</p>
        <ul className="list-disc space-y-0.5 pl-5">
          {reliability.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

const SIGNATURE_TONE: Record<string, "outline" | "destructive" | "secondary"> = {
  good: "secondary",
  not_checked: "outline",
};

/** The host's repositories as the agent read them: one row each, with the signature state. */
export function RepoHealthTable({ report }: { report: RepoHealthReport }) {
  const problemsOf = (r: RepoEvidenceRow) => report.assessment?.problems.filter((p) => p.repoId === r.id) ?? [];
  return (
    <div className="space-y-2" data-repo-health-table>
      <ul className="divide-y rounded-xl border text-sm">
        {report.repos.length === 0 ? <li className="px-4 py-3 text-muted-foreground">No enabled repositories.</li> : null}
        {report.repos.map((r) => {
          const problems = problemsOf(r);
          return (
            <li key={r.id} className="space-y-0.5 px-4 py-3" data-repo-row={r.id}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{r.label}</span>
                <Badge variant={problems.length > 0 ? "destructive" : (SIGNATURE_TONE[r.signature] ?? "outline")}>
                  {r.signature.replaceAll("_", " ")}
                </Badge>
                {r.keyId ? <span className="text-xs text-muted-foreground">key {r.keyId}</span> : null}
              </div>
              <p className="text-xs text-muted-foreground">
                {[
                  r.releaseDate ? `Release dated ${day(r.releaseDate)}` : "",
                  r.validUntil ? `valid until ${day(r.validUntil)}` : "",
                  r.metadataTime ? `metadata cached ${day(r.metadataTime)}` : "",
                  r.signedBy ?? "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
              {problems.map((p) => (
                <p key={p.code} className="text-xs text-amber-800 dark:text-amber-300">
                  {repoCodeLabel(p.code)}: {p.detail}
                </p>
              ))}
            </li>
          );
        })}
      </ul>
      <p className="text-xs text-muted-foreground">
        {report.lastRefresh ? `Host last refreshed its indexes ${day(report.lastRefresh)} (${report.lastRefreshSource ?? "unknown source"}). ` : "No record of the host refreshing its indexes. "}
        Read by the agent without refreshing anything.
        {report.limits?.length ? ` Could not check: ${report.limits.join("; ")}.` : ""}
      </p>
    </div>
  );
}

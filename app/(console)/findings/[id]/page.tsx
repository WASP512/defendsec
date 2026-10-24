import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/console-ui";
import { SeverityBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { getFindingDetail } from "@/lib/findings";
import { feedLabel, fixLabel } from "@/lib/findings-model";

export const dynamic = "force-dynamic";

/** One finding with the evidence it was computed from. */
export default async function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const n = Number(id);
  if (!Number.isInteger(n) || n < 1) notFound();
  const detail = await getFindingDetail(n);
  if (!detail) notFound();
  const { finding, advisory, range, snapshot } = detail;

  const rows: [string, React.ReactNode][] = [
    ["Host", <Link key="h" href={`/devices/${finding.deviceId}`} className="underline">{finding.hostname || finding.deviceId}</Link>],
    ["Package", `${finding.package}${finding.sourcePackage && finding.sourcePackage !== finding.package ? ` (source ${finding.sourcePackage})` : ""}`],
    ["Installed", finding.installed],
    ["Fix", fixLabel(finding)],
    ["Why", finding.reason],
    ["Basis", finding.basis === "distro" ? "The distribution's own advisory" : "Upstream version floor (software the distribution does not ship)"],
    ["Open since", finding.firstSeen],
    ["Last confirmed", finding.lastSeen],
    ["Closed", finding.resolvedAt ?? "still open"],
  ];
  const evidence: [string, React.ReactNode][] = [
    ["Advisory", finding.advisoryId],
    ["Range", finding.rangeId === null ? "—" : range ? `${finding.rangeId} (${range.ecosystem}${range.distro ? `, ${range.distro} ${range.release || "all releases"}` : ""}, ${range.fixState})` : `${finding.rangeId} (replaced by a later feed sync)`],
    ["Feed", feedLabel(finding)],
    ["Snapshot", finding.snapshotId === null ? "—" : String(finding.snapshotId)],
  ];

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        title={finding.cve || finding.advisoryId}
        eyebrow={<Link href="/advisories" className="underline">Advisories</Link>}
        description={advisory?.summary || finding.summary || "No summary in the feed."}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            {finding.kev ? <Badge variant="destructive">CISA KEV</Badge> : null}
            {finding.epss !== null ? <Badge variant="outline">EPSS {(finding.epss * 100).toFixed(1)}%</Badge> : null}
            {finding.cvss !== null ? <Badge variant="outline">CVSS {finding.cvss}</Badge> : null}
          </div>
        }
      />
      <Table>
        <TableBody>
          {rows.map(([label, value]) => (
            <TableRow key={label}>
              <TableCell className="w-40 text-muted-foreground">{label}</TableCell>
              <TableCell className="break-all font-medium">{value}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Evidence</h2>
        <p className="text-sm text-muted-foreground">
          What this finding was computed from, so it can be reproduced against the same feed data.
        </p>
        <Table>
          <TableBody>
            {evidence.map(([label, value]) => (
              <TableRow key={label}>
                <TableCell className="w-40 text-muted-foreground">{label}</TableCell>
                <TableCell className="break-all font-medium">{value}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {snapshot ? (
          <Table>
            <TableBody>
              {snapshot.feeds.map((feed) => (
                <TableRow key={feed.name}>
                  <TableCell className="w-40 text-muted-foreground">{feed.name}</TableCell>
                  <TableCell className="break-all text-sm">
                    fetched {feed.fetchedAt} · {feed.recordCount} records · sha256 {feed.sha256}
                    <br />
                    <span className="text-muted-foreground">{feed.url}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
      </section>
    </div>
  );
}

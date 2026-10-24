import Link from "next/link";
import { notFound } from "next/navigation";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { getRmmDevice } from "@/lib/rmm";
import { ago, coverageText, isRmmDeviceId, osSupportLine, plural } from "@/lib/rmm-model";
import { supportedOs } from "@/lib/supported-os";
import { warmOsCalendar } from "@/lib/os-calendar";

export const dynamic = "force-dynamic";

function day(iso: string | null) {
  return iso ? iso.slice(0, 10) : "—";
}

export default async function RmmDevicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!isRmmDeviceId(id)) notFound();
  const d = await getRmmDevice(id);
  if (!d) notFound();
  await warmOsCalendar();
  const now = new Date();
  const cov = coverageText(d.coverage);
  const unsupported = supportedOs({ platform: "windows", osName: d.osCaption, osVersion: d.osVersion }, undefined, undefined, now) === false;
  const SRC = "Datto RMM";
  const facts: [string, string, string][] = [
    ["Operating system", `${d.osCaption || "—"} ${d.osVersion}`.trim() + (d.osDisplay ? ` (${d.osDisplay})` : ""), `${SRC} audit`],
    ["Build", d.osBuild || "—", `${SRC} audit`],
    ["Serial number", d.serial || "—", `${SRC} audit (BIOS)`],
    ["Last audit", `${day(d.lastAuditAt)} (${ago(d.lastAuditAt, now)})`, SRC],
    ["Last seen by RMM", `${ago(d.lastSeen, now)}${d.online ? " · online when read" : ""}`, SRC],
    ["Last reboot", day(d.lastReboot), SRC],
    ["Reboot required", d.rebootRequired ? "yes" : "no", SRC],
    ["Antivirus", d.antivirus || "—", SRC],
    ["RMM patch status", d.patchStatus || "—", SRC],
    ["Updates", `${d.patchesApprovedPending} approved and pending, ${d.patchesNotApproved} not approved, ${d.patchesInstalled} installed`, SRC],
    ["Read", ago(d.collectedAt, now), "DefendSec"],
  ];
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title={d.hostname}
        eyebrow={
          <Link href="/rmm" className="underline">
            Datto RMM
          </Link>
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">Source: Datto RMM</Badge>
            <Badge variant={cov.tone === "good" ? "default" : "outline"}>{cov.label}</Badge>
            {unsupported ? <Badge variant="destructive">unsupported OS</Badge> : null}
          </span>
        }
      />

      {d.coverage !== "covered" ? (
        <CoverageBanner notice={{ tone: "amber", title: cov.label, detail: `${cov.detail}${d.reason ? ` ${d.reason}` : ""}` }} />
      ) : d.reason ? (
        <p className="text-sm text-muted-foreground">{d.reason}</p>
      ) : null}
      {d.collectError && d.coverage === "covered" ? <CoverageBanner notice={{ tone: "amber", title: "Part of this device could not be read", detail: d.collectError }} /> : null}
      {unsupported ? (
        <div role="alert" className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {osSupportLine(d, now)}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">{osSupportLine(d, now)}</p>
      )}
      {d.mergedInto ? (
        <p className="rounded-lg border px-4 py-3 text-sm">
          This is also an enrolled DefendSec agent (matched by {d.dedupeBasis}):{" "}
          <Link href={`/devices/${d.mergedInto}`} className="underline">
            open the agent view
          </Link>
          . Both sources are kept; the host list counts the machine once. Each fact below says which source it came from.
        </p>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-lg">Facts</CardTitle>
            <CardDescription>Every row names where it came from.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableBody>
                {facts.map(([k, v, src]) => (
                  <TableRow key={k}>
                    <TableCell className="w-48 text-muted-foreground">{k}</TableCell>
                    <TableCell>{v}</TableCell>
                    <TableCell className="text-right text-xs text-muted-foreground">{src}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Findings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            {d.coverage === "covered" ? (
              <p>
                {d.findingsOpen === 0
                  ? "No open findings from the missing updates."
                  : `${plural(d.findingsOpen, "open finding")} from ${plural(d.kbsMapped, "missing update")} known to Microsoft's feed.`}
                {d.kevOpen > 0 ? <span className="text-destructive"> {d.kevOpen} exploited in the wild.</span> : null}
              </p>
            ) : (
              <p className="text-muted-foreground">Not assessed, so no claim is made either way. Findings from the last assessment stay listed until fresh evidence replaces them.</p>
            )}
            <p>
              <Link href="/advisories" className="underline">
                Fix this week
              </Link>
            </p>
          </CardContent>
        </Card>
      </div>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Updates RMM lists as not installed ({d.patches.length})</h2>
        {d.patches.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {d.coverage === "covered" ? "RMM lists no missing updates for this device." : "Not read: this list says nothing until the device is assessed."}
          </p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Update</TableHead>
                  <TableHead>Status in RMM</TableHead>
                  <TableHead className="hidden md:table-cell">Severity</TableHead>
                  <TableHead className="hidden md:table-cell">Released</TableHead>
                  <TableHead>Fixes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.patches.map((p) => (
                  <TableRow key={p.uid}>
                    <TableCell className="max-w-md">
                      <span className="font-medium">{p.kb || "no KB number"}</span>
                      <span className="block text-xs text-muted-foreground">{p.title}</span>
                    </TableCell>
                    <TableCell>{p.status === "APPROVED_PENDING" ? "approved, waiting to install" : p.status === "NOT_APPROVED" ? "not approved" : p.status}</TableCell>
                    <TableCell className="hidden md:table-cell">{p.severity.toLowerCase()}</TableCell>
                    <TableCell className="hidden md:table-cell">{day(p.releaseDate)}</TableCell>
                    <TableCell>
                      {p.cves > 0 ? (
                        <>
                          {plural(p.cves, "vulnerability", "vulnerabilities")}
                          {p.kev > 0 ? (
                            <Badge variant="destructive" className="ml-2">
                              {p.kev} exploited
                            </Badge>
                          ) : null}
                        </>
                      ) : !p.kb ? (
                        <span className="text-muted-foreground">no KB, cannot be mapped</span>
                      ) : p.mapped ? (
                        <span className="text-muted-foreground">none open</span>
                      ) : (
                        <span className="text-muted-foreground">not in Microsoft&apos;s feed</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Installed software ({d.software.length})</h2>
        <p className="text-sm text-muted-foreground">
          Datto RMM reports a name and a version, with no publisher or package identity. Vulnerabilities in these applications are{" "}
          <strong>not assessed</strong>; this list is inventory only.
        </p>
        {d.software.length > 0 ? (
          <div className="max-h-96 overflow-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.software.map((s, i) => (
                  <TableRow key={`${s.name}-${i}`}>
                    <TableCell>{s.name}</TableCell>
                    <TableCell className="text-muted-foreground">{s.version}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : null}
      </section>
    </div>
  );
}

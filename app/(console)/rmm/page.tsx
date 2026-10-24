import Link from "next/link";
import { Monitor } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { RmmPanel } from "@/components/rmm-panel";
import { RmmSummaryCard } from "@/components/rmm-summary-card";
import { getRmmDevices, getRmmStatus, getRmmSyncs } from "@/lib/rmm";
import { ago, coverageText, osSupportLine, plural } from "@/lib/rmm-model";
import { isReadOnlySession } from "@/lib/auth";
import { supportedOs } from "@/lib/supported-os";

export const dynamic = "force-dynamic";

export default async function RmmPage() {
  const [status, devices, syncs, readOnly] = await Promise.all([getRmmStatus(), getRmmDevices(), getRmmSyncs(10), isReadOnlySession()]);
  const now = new Date();
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Datto RMM"
        description={
          <>
            Windows coverage with nothing new installed on the PCs: the OS, the installed software and the updates Datto RMM
            lists as missing, read through its read-only API for one site. A missing update that fixes an exploited
            vulnerability ranks first in{" "}
            <Link href="/advisories" className="underline">
              Fix this week
            </Link>
            .
          </>
        }
      />

      {status === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Datto RMM status unavailable",
            detail: "The control plane could not be reached, or it is older than the RMM API. An empty page here would not mean there are no Windows devices.",
          }}
        />
      ) : (
        <>
          {!status.credentials.configured ? (
            <CoverageBanner
              notice={{
                tone: "amber",
                title: "Datto RMM is not connected",
                detail: status.credentials.problem ?? "Datto RMM is not configured.",
              }}
            />
          ) : null}
          {status.credentials.warnings.map((w) => (
            <CoverageBanner key={w} notice={{ tone: "amber", title: "Credential file permissions", detail: w }} />
          ))}
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Site</CardTitle>
                  <CardDescription>
                    {status.summary.settings.configured ? (
                      <>
                        Reading <strong>{status.summary.settings.siteName}</strong>
                        {status.summary.settings.selectedBy ? <> (chosen by {status.summary.settings.selectedBy})</> : null}. One instance reads one
                        site.
                      </>
                    ) : (
                      "One instance reads one RMM site. Pick it from the list RMM gives."
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <RmmPanel status={status} readOnly={readOnly} />
                </CardContent>
              </Card>
            </div>
            <RmmSummaryCard status={status} />
          </div>

          <Card data-rmm-not-assessed>
            <CardHeader>
              <CardTitle className="text-lg">What this does not cover</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {status.notAssessed.map((n) => (
                <div key={n.what}>
                  <p className="font-medium">{n.what}: not assessed</p>
                  <p className="text-muted-foreground">{n.why}</p>
                </div>
              ))}
              <p className="text-muted-foreground">{status.readOnlyNote}</p>
            </CardContent>
          </Card>
        </>
      )}

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Devices</h2>
        {devices === null ? (
          <p className="text-sm text-muted-foreground">The device list could not be read.</p>
        ) : devices.length === 0 ? (
          <EmptyState
            title="No devices read yet"
            description="Select a site and read it. Devices that are not Windows (printers, Macs, Linux) are not read."
            icon={Monitor}
          />
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Operating system</TableHead>
                  <TableHead>Assessment</TableHead>
                  <TableHead className="hidden md:table-cell">Last audit</TableHead>
                  <TableHead className="hidden lg:table-cell">Updates missing</TableHead>
                  <TableHead>Open findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((d) => {
                  const cov = coverageText(d.coverage);
                  const unsupported = supportedOs({ platform: "windows", osName: d.osCaption, osVersion: d.osVersion }, undefined, now) === false;
                  return (
                    <TableRow key={d.id}>
                      <TableCell className="min-w-40">
                        <Link href={`/rmm/devices/${d.id}`} className="font-medium hover:underline">
                          {d.hostname}
                        </Link>
                        {d.mergedInto ? (
                          <Badge variant="outline" className="ml-2" title={`Also an enrolled agent (matched by ${d.dedupeBasis})`}>
                            also agent
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        {d.osCaption || "—"}
                        <span className="block text-xs text-muted-foreground">
                          {d.osVersion}
                          {d.osDisplay ? ` · ${d.osDisplay}` : ""}
                        </span>
                        {unsupported ? (
                          <Badge variant="destructive" title={osSupportLine(d, now)}>
                            unsupported
                          </Badge>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Badge variant={cov.tone === "good" ? "default" : "outline"} title={d.reason || cov.detail}>
                          {cov.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="hidden text-muted-foreground md:table-cell">{ago(d.lastAuditAt, now)}</TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {d.patchesApprovedPending + d.patchesNotApproved}
                        <span className="text-xs text-muted-foreground">
                          {" "}
                          ({d.patchesApprovedPending} approved, {d.patchesNotApproved} not)
                        </span>
                      </TableCell>
                      <TableCell>
                        {d.coverage === "covered" || d.findingsOpen > 0 ? d.findingsOpen : "—"}
                        {d.kevOpen > 0 ? (
                          <Badge variant="destructive" className="ml-2">
                            {d.kevOpen} exploited
                          </Badge>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Recent reads</h2>
        {syncs === null || syncs.length === 0 ? (
          <p className="text-sm text-muted-foreground">{syncs === null ? "The history could not be read." : "No read yet."}</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Finished</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Devices</TableHead>
                  <TableHead className="hidden md:table-cell">Not assessed</TableHead>
                  <TableHead className="hidden md:table-cell">Requests</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {syncs.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell title={s.finishedAt}>{ago(s.finishedAt, now)}</TableCell>
                    <TableCell>
                      <Badge variant={s.status === "ok" ? "default" : "outline"}>{s.status === "ok" ? "read" : s.status === "partial" ? "partly read" : "not assessed"}</Badge>
                      {s.reason ? <span className="mt-1 block max-w-md text-xs text-muted-foreground">{s.reason}</span> : null}
                    </TableCell>
                    <TableCell>
                      {s.windows} Windows of {s.devices}
                      {s.skipped ? <span className="text-xs text-muted-foreground"> ({s.skipped} not Windows)</span> : null}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {s.stale + s.unreadable > 0 ? `${plural(s.stale, "stale audit")}, ${s.unreadable} unreadable` : "none"}
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{s.requests}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <details className="rounded-xl border p-4 text-sm" data-rmm-setup>
        <summary className="cursor-pointer font-medium">Connect Datto RMM (administrator setup)</summary>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-muted-foreground">
          <li>
            In Datto RMM: <strong>Setup &gt; Global Settings &gt; Access Control</strong>, turn on <strong>Enable API Access</strong>.
          </li>
          <li>
            <strong>Setup &gt; Security Levels</strong>: create a level for DefendSec that can only view, with device visibility limited to this
            client&apos;s site: <strong>Sites &gt; Sites: View</strong>, <strong>Sites &gt; Devices: View</strong> and{" "}
            <strong>Setup &gt; Global Settings: View</strong> (the site list needs it), every other permission None, all remote tools off.
            Then <strong>Setup &gt; Users</strong>: create a dedicated user with that level (not a person&apos;s account), and give its API
            Component Level no components.
          </li>
          <li>
            Open that user and click <strong>Generate API Keys</strong>. Copy the <strong>API Key</strong>, the <strong>API Secret Key</strong> (shown once)
            and the <strong>API URL</strong> (https://&lt;platform&gt;-api.centrastage.net).
          </li>
          <li>
            On the DefendSec server, put the key and the secret each in its own file readable only by the apid service account (mode 0600), and set{" "}
            <code>DEFENDSEC_RMM_API_URL</code>, <code>DEFENDSEC_RMM_KEY_FILE</code> and <code>DEFENDSEC_RMM_SECRET_FILE</code> for apid. They are never typed
            into this page.
          </li>
          <li>
            Add <code>msrc</code> to <code>DEFENDSEC_FEEDS_ENABLED</code> and run <code>defendsec-feeds sync</code>: that is Microsoft&apos;s list of which update fixes which
            vulnerability.
          </li>
          <li>
            Revoke later by deleting the API keys on the user&apos;s page, or deactivating the user. Full steps are in <code>docs/DATTO-RMM.md</code>.
          </li>
        </ol>
      </details>
    </div>
  );
}

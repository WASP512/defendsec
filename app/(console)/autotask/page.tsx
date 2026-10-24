import Link from "next/link";
import { Ticket } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { AutotaskPanel } from "@/components/autotask-panel";
import { getAutotaskRuns, getAutotaskStatus, getAutotaskTickets } from "@/lib/autotask-api";
import { opKindLabel, opStatusLabel, runResultLabel, runSummary, stateLabel, urgencyLabel, withLabel, type AutotaskOp, type AutotaskRun } from "@/lib/autotask-model";
import { agoLabel } from "@/lib/surface-exposure";
import { isReadOnlySession } from "@/lib/auth";

export const dynamic = "force-dynamic";

function OpCard({ op, run }: { op: AutotaskOp; run: AutotaskRun }) {
  const body = op.create?.description ?? op.note ?? "";
  return (
    <div className="space-y-2 rounded-xl border p-4" data-autotask-op={op.kind} data-op-status={op.status}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={op.kind === "create" ? "default" : "outline"}>{opKindLabel(op.kind)}</Badge>
        {op.urgency ? <Badge variant="outline">{urgencyLabel(op.urgency)}</Badge> : null}
        <span className="text-xs text-muted-foreground">{opStatusLabel(op.status, run.mode)}</span>
        {op.ticketNumber ? <span className="text-xs text-muted-foreground">ticket {op.ticketNumber}</span> : null}
      </div>
      <p className="font-medium">{op.title}</p>
      {op.reason ? <p className="text-sm text-muted-foreground">{op.reason}</p> : null}
      {op.error ? <p className="text-sm text-destructive">{op.error}</p> : null}
      {op.create ? (
        <dl className="grid gap-x-4 gap-y-1 text-sm sm:grid-cols-2">
          <div>
            <dt className="inline text-muted-foreground">Company </dt>
            <dd className="inline">{op.create.companyID}</dd>
          </div>
          <div>
            <dt className="inline text-muted-foreground">Queue </dt>
            <dd className="inline">{withLabel(op.labels, "queue", op.create.queueID, "category default")}</dd>
          </div>
          <div>
            <dt className="inline text-muted-foreground">Priority </dt>
            <dd className="inline">{withLabel(op.labels, "priority", op.create.priority, "none")}</dd>
          </div>
          <div>
            <dt className="inline text-muted-foreground">Status </dt>
            <dd className="inline">{withLabel(op.labels, "status", op.create.status, "none")}</dd>
          </div>
          <div>
            <dt className="inline text-muted-foreground">Issue / sub-issue </dt>
            <dd className="inline">
              {withLabel(op.labels, "issueType", op.create.issueType, "none")} / {withLabel(op.labels, "subIssueType", op.create.subIssueType, "none")}
            </dd>
          </div>
          <div>
            <dt className="inline text-muted-foreground">Due </dt>
            <dd className="inline">{op.create.dueDateTime ?? "category default"} (UTC)</dd>
          </div>
        </dl>
      ) : null}
      {body ? (
        <details>
          <summary className="cursor-pointer text-sm text-muted-foreground">{op.create ? "Exact description" : "Exact note"}</summary>
          <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap rounded-lg bg-muted p-3 text-xs">{body}</pre>
        </details>
      ) : null}
    </div>
  );
}

export default async function AutotaskPage() {
  const [status, runs, tickets, readOnly] = await Promise.all([getAutotaskStatus(), getAutotaskRuns(10), getAutotaskTickets(), isReadOnlySession()]);
  const now = new Date().getTime();
  const dry = status?.latestDryRun ?? null;
  const last = status?.latestRun ?? null;
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Autotask tickets"
        description={
          <>
            Turns{" "}
            <Link href="/advisories" className="underline">
              Fix this week
            </Link>{" "}
            into tickets in the queue your technicians already work from: one ticket per remediation action (&quot;Update openssl on 4 hosts&quot;, not one per CVE and host), a
            note when a host joins or a finding is fixed, and never a second ticket for the same thing. A dry run shows the exact tickets and changes nothing; it is the
            default, and opening tickets for real needs a dry run for exactly these settings first.
          </>
        }
      />

      {status === null ? (
        <CoverageBanner
          notice={{
            tone: "amber",
            title: "Autotask status unavailable",
            detail: "The control plane could not be reached, or it is older than the Autotask API. An empty page here would not mean nothing was ticketed.",
          }}
        />
      ) : (
        <>
          {!status.credentials.configured ? (
            <CoverageBanner
              notice={{ tone: "amber", title: "Autotask is not connected", detail: status.credentials.problem ?? "Autotask credentials are not configured." }}
            />
          ) : null}
          {status.credentials.warnings.map((w) => (
            <CoverageBanner key={w} notice={{ tone: "amber", title: "Credential", detail: w }} />
          ))}
          {last && last.status === "not_run" ? (
            <CoverageBanner
              notice={{ tone: "amber", title: `The last ${last.mode === "dry_run" ? "dry run" : "run"} did not run`, detail: last.problems.join(" ") || "No reason recorded." }}
            />
          ) : null}
          {dry && !dry.verified && dry.status !== "not_run" ? (
            <CoverageBanner
              notice={{
                tone: "amber",
                title: "The latest dry run did not read Autotask",
                detail: `${dry.unverifiedWhy || "No reason recorded."} It cannot unlock opening tickets.`,
              }}
            />
          ) : null}

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Company and ticket settings</CardTitle>
              <CardDescription>
                {status.settings.companyId ? (
                  <>
                    Opening tickets in company <code>{status.settings.companyId}</code>
                    {dry?.companyName ? <> ({dry.companyName})</> : null}
                    {status.settings.updatedBy ? <>, set by {status.settings.updatedBy}</> : null}. Mode:{" "}
                    <strong>{status.settings.mode === "live" ? "live" : "dry run"}</strong>.
                  </>
                ) : (
                  "One DefendSec instance maps to one Autotask company. Create the API user first (setup guide below), then choose the company and the values your tickets carry."
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <AutotaskPanel status={status} readOnly={readOnly} />
              <p className="mt-4 text-xs text-muted-foreground">{status.writeNote}</p>
            </CardContent>
          </Card>

          <section className="space-y-3" data-autotask-dry-run>
            <h2 className="text-lg font-semibold">Latest dry run: the tickets it would open</h2>
            {dry === null ? (
              <EmptyState
                title="No dry run yet"
                description="Choose the company and the values above, save, then show the tickets. Nothing is sent to Autotask by a dry run."
                icon={Ticket}
              />
            ) : (
              <>
                <p className="text-sm text-muted-foreground" title={dry.finishedAt}>
                  {agoLabel(dry.finishedAt, now)} by {dry.triggeredBy}: {runSummary(dry)}.{" "}
                  {dry.verified
                    ? `Read from Autotask (${dry.companyName || "company"}), ${dry.requests} requests: the picklist values are current and the tickets below are what a live run would send.`
                    : "Autotask was not read, so these are exactly what would be sent but are not checked against it."}
                </p>
                {dry.problems.length > 0 ? (
                  <ul className="list-disc space-y-1 pl-5 text-sm text-destructive">
                    {dry.problems.map((p) => (
                      <li key={p}>{p}</li>
                    ))}
                  </ul>
                ) : null}
                {dry.ops.length === 0 && dry.problems.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Nothing to open or add: every action in Fix this week at or above the threshold already has its ticket, or there is none.</p>
                ) : null}
                <div className="space-y-3">
                  {dry.ops.map((op, i) => (
                    <OpCard key={`${op.tag}-${op.kind}-${i}`} op={op} run={dry} />
                  ))}
                </div>
              </>
            )}
          </section>

          {last && last.mode === "live" ? (
            <section className="space-y-3" data-autotask-live-run>
              <h2 className="text-lg font-semibold">Latest live run</h2>
              <p className="text-sm text-muted-foreground" title={last.finishedAt}>
                {agoLabel(last.finishedAt, now)} by {last.triggeredBy} ({runResultLabel(last.status)}): {runSummary(last)}.
              </p>
              <div className="space-y-3">
                {last.ops.map((op, i) => (
                  <OpCard key={`${op.tag}-${op.kind}-${i}`} op={op} run={last} />
                ))}
              </div>
            </section>
          ) : null}
        </>
      )}

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Tickets DefendSec follows</h2>
        {tickets === null ? (
          <p className="text-sm text-muted-foreground">The tickets could not be read.</p>
        ) : tickets.length === 0 ? (
          <p className="text-sm text-muted-foreground">No ticket has been opened yet.</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Ticket</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Urgency</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="hidden md:table-cell">Covers</TableHead>
                  <TableHead className="hidden md:table-cell">Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tickets.map((t) => (
                  <TableRow key={t.tag} data-autotask-ticket={t.tag}>
                    <TableCell className="whitespace-nowrap">{t.ticketNumber || `#${t.ticketId}`}</TableCell>
                    <TableCell className="max-w-md">
                      {t.title}
                      {t.generation > 1 ? <span className="ml-2 text-xs text-muted-foreground">(ticket {t.generation} for this action)</span> : null}
                    </TableCell>
                    <TableCell>{urgencyLabel(t.urgency)}</TableCell>
                    <TableCell>
                      <Badge variant={t.state === "open" ? "default" : "outline"}>{stateLabel(t.state)}</Badge>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">{t.members}</TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell" title={t.updatedAt}>
                      {agoLabel(t.updatedAt, now)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Recent runs</h2>
        {runs === null || runs.length === 0 ? (
          <p className="text-sm text-muted-foreground">{runs === null ? "The history could not be read." : "No run yet."}</p>
        ) : (
          <div className="overflow-x-auto rounded-xl border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Finished</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead className="hidden md:table-cell">Requests</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell title={r.finishedAt}>{agoLabel(r.finishedAt, now)}</TableCell>
                    <TableCell>{r.mode === "dry_run" ? "Dry run" : "Live"}</TableCell>
                    <TableCell>
                      <Badge variant={r.status === "ok" ? "default" : "outline"}>{runResultLabel(r.status)}</Badge>
                      <span className="mt-1 block max-w-md text-xs text-muted-foreground">{r.problems[0] ?? runSummary(r)}</span>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{r.requests}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <details className="rounded-xl border p-4 text-sm" data-autotask-setup>
        <summary className="cursor-pointer font-medium">Connect Autotask (administrator setup)</summary>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-muted-foreground">
          <li>
            In Autotask: <strong>Admin &gt; Resources/Users (HR) &gt; Resources/Users</strong>, <strong>New</strong>. Give the user an email-style name such as{" "}
            <code>defendsec-api@yourdomain</code>, and on the <strong>Security</strong> tab choose the security level <strong>API User (system)</strong> (API-only). Better: copy
            that level first and restrict the copy to Tickets, Ticket Notes and Companies. Set a long password and do not let it expire (an API user cannot change it).
          </li>
          <li>
            On the same <strong>Security</strong> tab, under <strong>API Tracking Identifier</strong>, choose <strong>Custom (Internal Integration)</strong>. The integration code
            that appears is the second half of the credential.
          </li>
          <li>
            Write the user&apos;s password to one file and the integration code to another on the DefendSec server, each a single line, <code>chmod 600</code>, and set{" "}
            <code>DEFENDSEC_AUTOTASK_SECRET_FILE</code> and <code>DEFENDSEC_AUTOTASK_CODE_FILE</code> for apid. Neither is ever typed into this page.
          </li>
          <li>
            Create a <strong>test queue</strong> (Admin &gt; Features &amp; Settings &gt; Service Desk &gt; Queues) and, ideally, a <strong>Source</strong> named DefendSec (same
            place, Sources) so a workflow rule can route these tickets. Use a test company first.
          </li>
          <li>
            Here: enter the API user&apos;s name, search the company, wait for the lists, choose the queue, status, priorities, issue and sub-issue type, note type and visibility.
            Save, <strong>Show me the tickets</strong>, read them, and only then <strong>Go live</strong>.
          </li>
          <li>
            Revoke later by deactivating the API user (or deleting its tracking identifier) in Autotask. Full steps and the sources for each call are in{" "}
            <code>docs/AUTOTASK.md</code>.
          </li>
        </ol>
      </details>
    </div>
  );
}

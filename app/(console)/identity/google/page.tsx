import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { GoogleIdentityPanel } from "@/components/google-identity-panel";
import { IdentitySummaryCard } from "@/components/identity-summary-card";
import { IdentityFindingsSection, IdentityRunsSection, IdentityTabs } from "@/components/identity-sections";
import { getGoogleStatus, getIdentityFindings, getIdentityRuns } from "@/lib/identity-api";
import { CHECK_ORDER_GOOGLE, checkLabel, runResultLabel } from "@/lib/identity-model";
import { agoLabel } from "@/lib/surface-exposure";
import { isReadOnlySession } from "@/lib/auth";

export const dynamic = "force-dynamic";

function observedLine(check: string, o: Record<string, unknown>): string {
  const n = (k: string) => (typeof o[k] === "number" ? (o[k] as number) : 0);
  switch (check) {
    case "mfa":
      return `${n("activeUsers")} active users: ${n("enrolled")} enrolled in 2-Step Verification, ${n("notEnrolled")} not (${n("administratorsNotEnrolled")} of them administrators); enforced for all but ${n("notEnforced")}; ${n("guestsSkipped")} guest(s) and ${n("suspendedOrArchivedSkipped")} suspended or archived account(s) left out.`;
    case "admin-roles":
      return `${n("superAdmins")} super administrators (limit ${n("superAdminLimit")}); ${n("delegatedAdmins")} delegated administrator(s).`;
    case "inbox-rules":
      return `${n("mailboxesRead")} of ${n("mailboxesEligible")} mailboxes read (${n("noMailbox")} without one, ${n("unreadable")} unreadable, ${n("skipped")} skipped), ${n("filtersRead")} filters.`;
  }
  return "";
}

export default async function GoogleIdentityPage() {
  const [status, findings, runs, readOnly] = await Promise.all([getGoogleStatus(), getIdentityFindings(false, "google"), getIdentityRuns(10, "google"), isReadOnlySession()]);
  const now = new Date().getTime();
  const run = status?.latestRun ?? null;
  const cr = status?.credentials;
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <IdentityTabs active="google" />
      <PageHeader
        title="Identity: Google Workspace"
        description={
          <>
            How easily the client&apos;s Google Workspace accounts could be taken over, and how mail could be hidden or redirected once one is: who is not enrolled in
            2-Step Verification, whether it is enforced, how many super administrators there are, and Gmail forwarding and filters that send mail outside or hide it (the
            pattern behind a payment-redirection fraud). Read-only, through a service account with domain-wide delegation; no message is ever read. Findings rank in{" "}
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
            title: "Google Workspace status unavailable",
            detail: "The control plane could not be reached, or it is older than the Google Workspace identity API. An empty page here would not mean the accounts are in good order.",
          }}
        />
      ) : (
        <>
          {cr && !cr.configured ? (
            <CoverageBanner
              notice={{ tone: "amber", title: "Google Workspace is not connected", detail: cr.problem ?? "Google Workspace is not configured." }}
            />
          ) : null}
          {cr?.warnings.map((w) => (
            <CoverageBanner key={w} notice={{ tone: "amber", title: "Credential", detail: w }} />
          ))}
          {run && run.status === "not_assessed" ? (
            <CoverageBanner
              notice={{
                tone: "amber",
                title: "The last read could not assess anything",
                detail: `${run.reason || "No reason recorded."} The findings below are from earlier reads; nothing was resolved by this one.`,
              }}
            />
          ) : null}

          <div className="grid gap-4 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Domain</CardTitle>
                  <CardDescription>
                    {status.settings.configured ? (
                      <>
                        Reading the domain as <code>{status.settings.adminEmail}</code>
                        {status.settings.updatedBy ? <> (set by {status.settings.updatedBy})</> : null}. One instance reads one domain.
                      </>
                    ) : (
                      "One instance reads one domain. Create the service account first (setup guide below), then enter the administrator to act as."
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {cr?.clientEmail ? (
                    <p className="text-sm text-muted-foreground" data-identity-credential>
                      Signing in as service account <code className="break-all">{cr.clientEmail}</code>
                      {cr.clientId ? (
                        <>
                          {" "}
                          (client ID, the number the Admin console&apos;s domain-wide delegation entry must carry:{" "}
                          <code className="break-all" data-identity-client-id>
                            {cr.clientId}
                          </code>
                          )
                        </>
                      ) : null}
                      {cr.keyId ? (
                        <>
                          , key <code className="break-all">{cr.keyId}</code>
                        </>
                      ) : null}
                      {cr.projectId ? <>, project {cr.projectId}</> : null}. The key is a file on the server and is never shown here.
                    </p>
                  ) : null}
                  <GoogleIdentityPanel status={status} readOnly={readOnly} />
                </CardContent>
              </Card>
            </div>
            <IdentitySummaryCard summary={status.summary} />
          </div>

          <Card data-identity-checks>
            <CardHeader>
              <CardTitle className="text-lg">What the latest read covered</CardTitle>
              <CardDescription>
                {run ? (
                  <>
                    Read {agoLabel(run.finishedAt, now)} ({runResultLabel(run.status)}, {run.requests} requests). A check that could not run is missing evidence, never a
                    pass.
                  </>
                ) : (
                  "Nothing has been read yet."
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {run
                ? CHECK_ORDER_GOOGLE.map((c) => {
                    const st = run.checks.find((x) => x.check === c);
                    if (!st) return null;
                    return (
                      <div key={c} data-identity-check={c} data-assessed={st.assessed ? "yes" : "no"}>
                        <p className="font-medium">
                          {checkLabel(c, "google")} <Badge variant={st.assessed ? "default" : "outline"}>{st.assessed ? "assessed" : "not assessed"}</Badge>
                        </p>
                        <p className="text-muted-foreground">{st.assessed ? observedLine(c, st.observed) : st.reason}</p>
                        {st.assessed && (st.unassessedPrefixes?.length ?? 0) > 0 ? (
                          <p className="text-amber-700 dark:text-amber-400">
                            {st.unassessedPrefixes!.length} mailbox(es) could not be read or were skipped: their filters and forwarding are neither confirmed nor cleared by
                            this read.
                          </p>
                        ) : null}
                      </div>
                    );
                  })
                : null}
            </CardContent>
          </Card>

          <Card data-identity-not-assessed>
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

      <IdentityFindingsSection findings={findings} lastStatus={status?.summary.lastStatus} noun="domain" now={now} />

      <IdentityRunsSection runs={runs} now={now} />

      {status ? (
        <Card data-identity-permissions>
          <CardHeader>
            <CardTitle className="text-lg">Scopes the delegation needs</CardTitle>
            <CardDescription>
              OAuth scopes entered in the Admin console&apos;s domain-wide delegation list, next to the service account&apos;s client ID. Delegate one Gmail scope, not both.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {status.permissions.map((p) => (
              <div key={p.name}>
                <p className="font-medium">
                  <code className="break-all">{p.name}</code> <Badge variant={p.required ? "default" : "outline"}>{p.required ? "required" : "alternative"}</Badge>
                </p>
                <p className="text-muted-foreground">{p.why}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <details className="rounded-xl border p-4 text-sm" data-identity-setup>
        <summary className="cursor-pointer font-medium">Connect a Google Workspace domain (administrator setup)</summary>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-muted-foreground">
          <li>
            Open <strong>console.cloud.google.com</strong> and sign in with a Google account that may create projects. Create a project (name it <em>DefendSec read-only</em>).
            An MSP can use one project for every client: each client&apos;s super administrator authorises the same service account in step 5.
          </li>
          <li>
            <strong>APIs &amp; Services &gt; Library</strong>: find <strong>Admin SDK API</strong> and click <strong>Enable</strong>, then find <strong>Gmail API</strong> and click{" "}
            <strong>Enable</strong>. Without these, Google answers 403 and DefendSec says the API is not enabled.
          </li>
          <li>
            <strong>IAM &amp; Admin &gt; Service accounts &gt; Create service account</strong>. Name it <em>defendsec-readonly</em>, skip the optional role and user steps, and
            click <strong>Done</strong>. Open it and copy its numeric <strong>Unique ID</strong> (the OAuth client ID) for step 5.
          </li>
          <li>
            On the service account&apos;s <strong>Keys</strong> tab: <strong>Add key &gt; Create new key &gt; JSON &gt; Create</strong>. A file downloads once. Put it on the
            DefendSec server as <code>chmod 600</code> and set <code>DEFENDSEC_GWS_KEY_FILE</code> for apid to its path, then restart apid. The key is never typed into this page. (If
            Google refuses to create a key, an organisation policy blocks service account keys; ask the organisation&apos;s administrator.)
          </li>
          <li>
            In <strong>admin.google.com</strong>, signed in as a <strong>super administrator</strong> of the client&apos;s domain: <strong>Security &gt; Access and data control &gt; API
            controls &gt; Manage domain-wide delegation &gt; Add new</strong>. <strong>Client ID</strong>: the numeric ID from step 3. <strong>OAuth scopes</strong>: paste{" "}
            <code className="break-all">https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/gmail.settings.basic</code> (or, if you chose it below,{" "}
            <code className="break-all">gmail.readonly</code> in place of <code>gmail.settings.basic</code>). Click <strong>Authorize</strong>. It usually takes a few minutes and can take
            up to 24 hours.
          </li>
          <li>
            Enter above the email address of a <strong>super administrator</strong> to act as, choose the Gmail scope you delegated, and <strong>Connect this domain</strong>, then{" "}
            <strong>Read the domain now</strong>. Use an administrator with 2-Step Verification, ideally a dedicated one: a delegated administrator limited to some organisational units
            would show only those users.
          </li>
          <li>
            Revoke later by removing the delegation entry (<strong>Manage domain-wide delegation</strong> &gt; the entry &gt; <strong>Delete</strong>), and by deleting the key or the
            service account in the Cloud console. Full steps and the sources for each scope are in <code>docs/GOOGLE-WORKSPACE.md</code>.
          </li>
        </ol>
      </details>
    </div>
  );
}

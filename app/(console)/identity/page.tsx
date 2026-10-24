import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/console-ui";
import { CoverageBanner } from "@/components/finding-summary";
import { IdentityPanel } from "@/components/identity-panel";
import { IdentitySummaryCard } from "@/components/identity-summary-card";
import { IdentityFindingsSection, IdentityRunsSection, IdentityTabs } from "@/components/identity-sections";
import { getIdentityFindings, getIdentityRuns, getIdentityStatus } from "@/lib/identity-api";
import { CHECK_ORDER, certDaysLeft, checkLabel, runResultLabel } from "@/lib/identity-model";
import { agoLabel } from "@/lib/surface-exposure";
import { isReadOnlySession } from "@/lib/auth";

export const dynamic = "force-dynamic";

function observedLine(check: string, o: Record<string, unknown>): string {
  const n = (k: string) => (typeof o[k] === "number" ? (o[k] as number) : 0);
  switch (check) {
    case "mfa":
      return `${n("usersInReport")} users in the report: ${n("registered")} registered, ${n("notRegistered")} not (${n("administratorsWithoutMFA")} of them administrators); ${n("guestsSkipped")} guest(s) left out.`;
    case "admin-roles":
      return `${n("globalAdmins")} Global Administrators (limit ${n("globalAdminLimit")}); ${n("otherPrivilegedHolders")} account(s) hold another administrator role; ${n("globalAdminGroups")} group(s) hold Global Administrator (members not expanded).`;
    case "legacy-auth":
      return o.securityDefaultsEnabled === true
        ? "Security defaults are on, which blocks legacy authentication."
        : `Security defaults are off; ${n("conditionalAccessPolicies")} Conditional Access policies read.`;
    case "inbox-rules":
      return `${n("mailboxesRead")} of ${n("mailboxesEligible")} mailboxes read (${n("noMailbox")} without one, ${n("unreadable")} unreadable, ${n("skipped")} skipped), ${n("rulesRead")} rules.`;
  }
  return "";
}

export default async function IdentityPage() {
  const [status, findings, runs, readOnly] = await Promise.all([getIdentityStatus(), getIdentityFindings(false, "m365"), getIdentityRuns(10, "m365"), isReadOnlySession()]);
  const now = new Date().getTime();
  const run = status?.latestRun ?? null;
  const cert = status?.credentials.method === "certificate" ? certDaysLeft(status.credentials.notAfter, now) : null;
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <IdentityTabs active="m365" />
      <PageHeader
        title="Identity: Microsoft 365"
        description={
          <>
            How easily the client&apos;s Microsoft 365 accounts could be taken over, and how mail could be hidden or redirected once one is: who has no MFA,
            whether legacy sign-in is blocked, who is a Global Administrator, and inbox rules that forward mail outside or hide it (the pattern behind a
            payment-redirection fraud). Read-only, through a Microsoft app registration; no message is ever read. Findings rank in{" "}
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
            title: "Identity status unavailable",
            detail: "The control plane could not be reached, or it is older than the identity API. An empty page here would not mean the accounts are in good order.",
          }}
        />
      ) : (
        <>
          {!status.credentials.configured ? (
            <CoverageBanner
              notice={{
                tone: "amber",
                title: "Microsoft 365 is not connected",
                detail: status.credentials.problem ?? "Microsoft 365 is not configured.",
              }}
            />
          ) : null}
          {status.credentials.warnings.map((w) => (
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
                  <CardTitle className="text-lg">Tenant</CardTitle>
                  <CardDescription>
                    {status.settings.configured ? (
                      <>
                        Reading tenant <code>{status.settings.tenantId}</code>
                        {status.settings.updatedBy ? <> (set by {status.settings.updatedBy})</> : null}. One instance reads one tenant.
                      </>
                    ) : (
                      "One instance reads one tenant. Create the app registration first (setup guide below), then enter its IDs."
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {status.credentials.configured ? (
                    <p className="text-sm text-muted-foreground" data-identity-credential>
                      Signing in with a {status.credentials.method === "certificate" ? "certificate" : "client secret"}
                      {status.credentials.thumbprint ? (
                        <>
                          {" "}
                          (SHA-1 thumbprint, as the Entra portal lists it:{" "}
                          <code className="break-all" data-identity-thumbprint-sha1>
                            {status.credentials.thumbprintSha1}
                          </code>
                          ; SHA-256 <code className="break-all">{status.credentials.thumbprint}</code>
                          {cert !== null ? `, ${cert} days left` : ""})
                        </>
                      ) : null}
                      . The credential is a file on the server and is never shown here.
                    </p>
                  ) : null}
                  <IdentityPanel status={status} readOnly={readOnly} />
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
                    Read {agoLabel(run.finishedAt, now)} ({runResultLabel(run.status)}, {run.requests} requests). A check that could not run is
                    missing evidence, never a pass.
                  </>
                ) : (
                  "Nothing has been read yet."
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {run
                ? CHECK_ORDER.map((c) => {
                    const st = run.checks.find((x) => x.check === c);
                    if (!st) return null;
                    return (
                      <div key={c} data-identity-check={c} data-assessed={st.assessed ? "yes" : "no"}>
                        <p className="font-medium">
                          {checkLabel(c)}{" "}
                          <Badge variant={st.assessed ? "default" : "outline"}>{st.assessed ? "assessed" : "not assessed"}</Badge>
                        </p>
                        <p className="text-muted-foreground">{st.assessed ? observedLine(c, st.observed) : st.reason}</p>
                        {st.assessed && (st.unassessedPrefixes?.length ?? 0) > 0 ? (
                          <p className="text-amber-700 dark:text-amber-400">
                            {st.unassessedPrefixes!.length} mailbox(es) could not be read: their rules are neither confirmed nor cleared by this read.
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

      <IdentityFindingsSection findings={findings} lastStatus={status?.summary.lastStatus} noun="tenant" now={now} />

      <IdentityRunsSection runs={runs} now={now} />

      {status ? (
        <Card data-identity-permissions>
          <CardHeader>
            <CardTitle className="text-lg">Permissions the app registration needs</CardTitle>
            <CardDescription>Microsoft Graph application permissions, all read-only. Nothing here can change the tenant.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            {status.permissions.map((p) => (
              <div key={p.name}>
                <p className="font-medium">
                  <code>{p.name}</code> <Badge variant={p.required ? "default" : "outline"}>{p.required ? "required" : "optional"}</Badge>
                </p>
                <p className="text-muted-foreground">{p.why}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <details className="rounded-xl border p-4 text-sm" data-identity-setup>
        <summary className="cursor-pointer font-medium">Connect a Microsoft 365 tenant (administrator setup)</summary>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-muted-foreground">
          <li>
            Sign in to <strong>entra.microsoft.com</strong> as a Global Administrator of the client&apos;s tenant (admin consent needs one). Open{" "}
            <strong>Entra ID &gt; Overview</strong> and copy the <strong>Tenant ID</strong>.
          </li>
          <li>
            <strong>Entra ID &gt; App registrations &gt; New registration</strong>. Name it <em>DefendSec read-only</em>, choose{" "}
            <strong>Accounts in this organizational directory only</strong>, leave the redirect URI empty, <strong>Register</strong>. Copy the{" "}
            <strong>Application (client) ID</strong> from its Overview page.
          </li>
          <li>
            On the DefendSec server make a certificate: <code>openssl req -x509 -newkey rsa:2048 -nodes -keyout defendsec-m365.key -out defendsec-m365.crt -days 365 -subj &quot;/CN=defendsec-m365&quot;</code>,
            then <code>cat defendsec-m365.key defendsec-m365.crt &gt; defendsec-m365.pem</code> and <code>chmod 600 defendsec-m365.pem</code>. In the app:{" "}
            <strong>Certificates &amp; secrets &gt; Certificates &gt; Upload certificate</strong>, and upload the <code>.crt</code> only. The private key never leaves the server.
          </li>
          <li>
            <strong>API permissions &gt; Add a permission &gt; Microsoft Graph &gt; Application permissions</strong>: add <code>AuditLog.Read.All</code>,{" "}
            <code>Policy.Read.All</code>, <code>RoleManagement.Read.Directory</code>, <code>User.Read.All</code> and <code>MailboxSettings.Read</code>. Remove the default
            delegated <code>User.Read</code>. Then <strong>Grant admin consent for the tenant</strong>; every row must show a green <em>Granted</em>.
          </li>
          <li>
            The MFA report needs Microsoft Entra ID P1 or P2 and Conditional Access needs P1 (Microsoft 365 Business Premium includes P1). Without a licence those
            checks say <em>not assessed</em>; they never say clean.
          </li>
          <li>
            Set <code>DEFENDSEC_M365_CERT_FILE</code> to the <code>.pem</code> for apid and restart it. Enter the Tenant ID and the Application ID above and{" "}
            <strong>Connect this tenant</strong>, then <strong>Read the tenant now</strong>. A client secret works too (<code>DEFENDSEC_M365_SECRET_FILE</code>); a
            certificate is safer. Neither is ever typed into this page.
          </li>
          <li>
            MSP with one app for many clients: register it as multi-tenant once, with the same permissions, then send each client&apos;s Global Administrator the
            consent link <code>https://login.microsoftonline.com/&lt;client tenant id&gt;/adminconsent?client_id=&lt;application id&gt;</code>. Each instance then uses that
            client&apos;s tenant ID with the same application ID and certificate.
          </li>
          <li>
            Revoke later by deleting the app registration (or its certificate), or <strong>Enterprise applications &gt; the app &gt; Delete</strong>. Full steps and the
            sources for each permission are in <code>docs/M365.md</code>.
          </li>
        </ol>
      </details>
    </div>
  );
}

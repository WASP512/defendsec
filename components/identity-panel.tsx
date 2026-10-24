"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { looksLikeGuid, looksLikeTenant, parseList, type IdentityStatus } from "@/lib/identity-model";

type Feedback = { kind: "ok" | "error"; message: string } | null;

async function send(url: string, method: string, body?: unknown) {
  const res = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await res.json()) as Record<string, unknown>;
  } catch {
    // no body
  }
  if (!res.ok) throw new Error(typeof parsed.error === "string" ? parsed.error : `Request failed (${res.status})`);
  return parsed;
}

const selectClass =
  "h-8 w-full rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";
const areaClass =
  "min-h-16 w-full rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";

/**
 * Name the one Microsoft 365 tenant this instance reads, how strict the checks are,
 * and read it now. The certificate or secret is not entered here at all: apid reads
 * it from a file, so a credential never passes through a browser.
 */
export function IdentityPanel({ status, readOnly }: { status: IdentityStatus; readOnly: boolean }) {
  const s = status.settings;
  const [tenant, setTenant] = useState(s.tenantId);
  const [client, setClient] = useState(s.clientId);
  const [cloud, setCloud] = useState<string>(s.cloud);
  const [limit, setLimit] = useState(String(s.globalAdminMax));
  const [trusted, setTrusted] = useState(s.trustedDomains.join("\n"));
  const [finance, setFinance] = useState(s.financeTerms.join("\n"));
  const [folders, setFolders] = useState(s.resolveFolders);
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);

  async function run(key: string, work: () => Promise<string>) {
    setBusy(key);
    setFeedback(null);
    try {
      const message = await work();
      setFeedback({ kind: "ok", message });
      setTimeout(() => window.location.reload(), key === "sync" ? 6000 : 700);
    } catch (cause) {
      setFeedback({ kind: "error", message: cause instanceof Error ? cause.message : "Request failed" });
      setBusy(null);
    }
  }

  const n = Number(limit);
  const limitOk = Number.isInteger(n) && n >= 1 && n <= 50;
  const idsOk = looksLikeTenant(tenant) && looksLikeGuid(client);

  if (readOnly) {
    return <p className="text-sm text-muted-foreground">Connecting a tenant, changing the checks and reading now need an administrator.</p>;
  }

  return (
    <div className="space-y-4" data-identity-panel>
      {feedback ? (
        <p
          role="status"
          className={
            feedback.kind === "ok"
              ? "rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm"
              : "rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
          }
        >
          {feedback.message}
        </p>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="idn-tenant">Tenant ID (or domain)</Label>
          <Input id="idn-tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
          <p className="text-xs text-muted-foreground">The client&apos;s own directory ID, never &quot;common&quot;.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="idn-client">Application (client) ID</Label>
          <Input id="idn-client" value={client} onChange={(e) => setClient(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
          <p className="text-xs text-muted-foreground">Shown on the app registration. An MSP&apos;s multi-tenant app has one ID for every client.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="idn-cloud">Microsoft cloud</Label>
          <select id="idn-cloud" className={selectClass} value={cloud} onChange={(e) => setCloud(e.target.value)}>
            <option value="global">Worldwide (microsoft.com)</option>
            <option value="usgov">US Government (GCC High, DoD)</option>
            <option value="china">China (21Vianet)</option>
          </select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="idn-limit">Most Global Administrators before it is a finding</Label>
          <Input id="idn-limit" inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="idn-trusted">Trusted domains for forwarding</Label>
          <textarea id="idn-trusted" className={areaClass} value={trusted} onChange={(e) => setTrusted(e.target.value)} placeholder="partner.example.org" />
          <p className="text-xs text-muted-foreground">One per line. The tenant&apos;s own domains are already inside; a rule forwarding to these is not reported.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="idn-finance">Extra finance words</Label>
          <textarea id="idn-finance" className={areaClass} value={finance} onChange={(e) => setFinance(e.target.value)} placeholder="tax refund" />
          <p className="text-xs text-muted-foreground">Added to invoice, payment, remittance, wire, ACH, bank, QuickBooks, Intuit, payroll and the like.</p>
        </div>
      </div>

      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={folders} onChange={(e) => setFolders(e.target.checked)} />
        <span>
          Name the folder a rule moves mail to
          <span className="block text-xs text-muted-foreground">
            Needs the optional <code>Mail.ReadBasic.All</code> permission, which is broader than the others (it can read the sender and subject of messages in
            every mailbox; DefendSec only asks for folder names). Leave it off unless you grant it: without it, a move rule is reported only when it matches
            finance words.
          </span>
        </span>
      </label>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          disabled={busy !== null || !idsOk || !limitOk}
          onClick={() =>
            run("save", async () => {
              await send("/api/identity/settings", "PUT", {
                tenantId: tenant.trim(),
                clientId: client.trim(),
                cloud,
                globalAdminMax: n,
                trustedDomains: parseList(trusted),
                financeTerms: parseList(finance),
                resolveFolders: folders,
              });
              return "Saved. Read the tenant now to see the first result.";
            })
          }
        >
          {busy === "save" ? "Saving…" : s.configured ? "Save settings" : "Connect this tenant"}
        </Button>
        {!idsOk && (tenant || client) ? <span className="text-xs text-destructive">The tenant and application IDs must be GUIDs (the tenant may be a domain).</span> : null}
        {s.configured && status.credentials.configured ? (
          <Button
            variant="outline"
            size="sm"
            disabled={busy !== null || status.running}
            onClick={() =>
              run("sync", async () => {
                await send("/api/identity/sync", "POST");
                return "Reading the tenant now. This takes a few seconds for a small tenant; the page reloads in a moment.";
              })
            }
          >
            {status.running ? "A read is running…" : busy === "sync" ? "Starting…" : "Read the tenant now"}
          </Button>
        ) : null}
        <span className="text-sm text-muted-foreground">
          {status.scheduled ? `Also read automatically every ${status.intervalHours} hours.` : "Automatic reads are switched off on this server."}
        </span>
      </div>
    </div>
  );
}

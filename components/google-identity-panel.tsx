"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { looksLikeEmail, parseList, type GoogleStatus } from "@/lib/identity-model";

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

const areaClass =
  "min-h-16 w-full rounded-lg border border-input bg-transparent px-2.5 py-1.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30";

/**
 * Name the one Google Workspace administrator this instance reads as, how strict the
 * checks are, and read the domain now. The service account's key is not entered here
 * at all: apid reads it from a file, so a credential never passes through a browser.
 */
export function GoogleIdentityPanel({ status, readOnly }: { status: GoogleStatus; readOnly: boolean }) {
  const s = status.settings;
  const [admin, setAdmin] = useState(s.adminEmail);
  const [scope, setScope] = useState<string>(s.gmailScope);
  const [limit, setLimit] = useState(String(s.superAdminMax));
  const [trusted, setTrusted] = useState(s.trustedDomains.join("\n"));
  const [finance, setFinance] = useState(s.financeTerms.join("\n"));
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
  const adminOk = looksLikeEmail(admin);

  if (readOnly) {
    return <p className="text-sm text-muted-foreground">Connecting a domain, changing the checks and reading now need an administrator.</p>;
  }

  return (
    <div className="space-y-4" data-identity-panel="google">
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
          <Label htmlFor="gws-admin">Administrator to act as</Label>
          <Input id="gws-admin" type="email" value={admin} onChange={(e) => setAdmin(e.target.value)} placeholder="admin@client-domain.example" />
          <p className="text-xs text-muted-foreground">
            A super administrator of the domain. The service account acts as this user to list the users; a delegated administrator limited to some organisational
            units would show only those.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="gws-limit">Most super administrators before it is a finding</Label>
          <Input id="gws-limit" inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value)} />
          <p className="text-xs text-muted-foreground">Google names no maximum, only &quot;more than one&quot;. Four is DefendSec&apos;s judgement.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="gws-trusted">Trusted domains for forwarding</Label>
          <textarea id="gws-trusted" className={areaClass} value={trusted} onChange={(e) => setTrusted(e.target.value)} placeholder="partner.example.org" />
          <p className="text-xs text-muted-foreground">
            One per line. The domain&apos;s own names and aliases are already inside; forwarding to these is not reported.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="gws-finance">Extra finance words</Label>
          <textarea id="gws-finance" className={areaClass} value={finance} onChange={(e) => setFinance(e.target.value)} placeholder="tax refund" />
          <p className="text-xs text-muted-foreground">Added to invoice, payment, remittance, wire, ACH, bank, QuickBooks, Intuit, payroll and the like.</p>
        </div>
      </div>

      <fieldset className="space-y-2 text-sm">
        <legend className="font-medium">Gmail scope you delegated</legend>
        <label className="flex items-start gap-2">
          <input type="radio" name="gws-scope" className="mt-1" checked={scope === "settings.basic"} onChange={() => setScope("settings.basic")} />
          <span>
            <code>gmail.settings.basic</code>: cannot read mail, can change settings (default)
            <span className="block text-xs text-muted-foreground">
              A leaked key could not read a message, but could add forwarding or filters. DefendSec still only reads. Delegate the one you choose here, not both.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2">
          <input type="radio" name="gws-scope" className="mt-1" checked={scope === "readonly"} onChange={() => setScope("readonly")} />
          <span>
            <code>gmail.readonly</code>: cannot change settings, can read mail
            <span className="block text-xs text-muted-foreground">
              For where a write scope is not acceptable. DefendSec has no call that names a message, but a leaked key with this scope could read every mailbox.
            </span>
          </span>
        </label>
      </fieldset>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          disabled={busy !== null || !adminOk || !limitOk}
          onClick={() =>
            run("save", async () => {
              await send("/api/identity/google/settings", "PUT", {
                adminEmail: admin.trim(),
                gmailScope: scope,
                superAdminMax: n,
                trustedDomains: parseList(trusted),
                financeTerms: parseList(finance),
              });
              return "Saved. Read the domain now to see the first result.";
            })
          }
        >
          {busy === "save" ? "Saving…" : s.configured ? "Save settings" : "Connect this domain"}
        </Button>
        {!adminOk && admin ? <span className="text-xs text-destructive">That does not look like an email address.</span> : null}
        {s.configured && status.credentials.configured ? (
          <Button
            variant="outline"
            size="sm"
            disabled={busy !== null || status.running}
            onClick={() =>
              run("sync", async () => {
                await send("/api/identity/google/sync", "POST");
                return "Reading the domain now. This takes a few seconds for a small domain (one request pair per mailbox); the page reloads in a moment.";
              })
            }
          >
            {status.running ? "A read is running…" : busy === "sync" ? "Starting…" : "Read the domain now"}
          </Button>
        ) : null}
        <span className="text-sm text-muted-foreground">
          {status.scheduled ? `Also read automatically every ${status.intervalHours} hours.` : "Automatic reads are switched off on this server."}
        </span>
      </div>
    </div>
  );
}

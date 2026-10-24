"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { RmmSite, RmmStatus } from "@/lib/rmm-model";

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

/**
 * Pick the one RMM site this instance reads, and read it now. The site list is
 * RMM's own (never typed in), and the credentials are not entered here at all:
 * apid reads them from files, so a key or secret never passes through a browser.
 */
export function RmmPanel({ status, readOnly }: { status: RmmStatus; readOnly: boolean }) {
  const settings = status.summary.settings;
  const [sites, setSites] = useState<RmmSite[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [site, setSite] = useState(settings.siteUid);
  const [days, setDays] = useState(String(settings.staleAfterDays));
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);

  const canLoad = !readOnly && status.credentials.configured;
  useEffect(() => {
    if (!canLoad) return;
    let live = true;
    fetch("/api/rmm/sites")
      .then(async (res) => {
        const body = (await res.json().catch(() => ({}))) as { sites?: RmmSite[]; error?: string };
        if (!live) return;
        if (!res.ok) setLoadError(body.error ?? `Could not list the sites (${res.status})`);
        else setSites(body.sites ?? []);
      })
      .catch(() => live && setLoadError("The control plane could not be reached."));
    return () => {
      live = false;
    };
  }, [canLoad]);

  async function run(key: string, work: () => Promise<string>) {
    setBusy(key);
    setFeedback(null);
    try {
      const message = await work();
      setFeedback({ kind: "ok", message });
      setTimeout(() => window.location.reload(), key === "sync" ? 4000 : 700);
    } catch (cause) {
      setFeedback({ kind: "error", message: cause instanceof Error ? cause.message : "Request failed" });
      setBusy(null);
    }
  }

  const n = Number(days);
  const daysOk = Number.isInteger(n) && n >= 1 && n <= 90;

  return (
    <div className="space-y-4" data-rmm-panel>
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

      {readOnly ? (
        <p className="text-sm text-muted-foreground">Choosing the site and reading it now need an administrator.</p>
      ) : !status.credentials.configured ? (
        <p className="text-sm text-muted-foreground">Connect Datto RMM first (the credentials are files on the server, see the setup guide below).</p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-[2fr_1fr_auto] sm:items-end">
          <div className="space-y-1.5">
            <Label htmlFor="rmm-site">Site</Label>
            <select id="rmm-site" className={selectClass} value={site} onChange={(e) => setSite(e.target.value)} disabled={!sites || busy !== null}>
              <option value="">{sites ? "Choose a site…" : loadError ? "Could not list sites" : "Loading sites…"}</option>
              {(sites ?? []).map((s) => (
                <option key={s.uid} value={s.uid}>
                  {s.name} ({s.devices} devices)
                </option>
              ))}
            </select>
            {loadError ? <p className="text-xs text-destructive">{loadError}</p> : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rmm-stale">Audit is stale after (days)</Label>
            <Input id="rmm-stale" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
          </div>
          <Button
            disabled={busy !== null || !site || !daysOk}
            onClick={() =>
              run("save", async () => {
                await send("/api/rmm/settings", "PUT", { siteUid: site, staleAfterDays: n });
                return "Site saved. Read it now to bring its devices in.";
              })
            }
          >
            {busy === "save" ? "Saving…" : settings.configured ? "Change site" : "Use this site"}
          </Button>
        </div>
      )}

      {!readOnly && settings.configured && status.credentials.configured ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            disabled={busy !== null || status.running}
            onClick={() =>
              run("sync", async () => {
                await send("/api/rmm/sync", "POST");
                return "Reading the site now. This takes about a second per device; the page reloads in a moment.";
              })
            }
          >
            {status.running ? "A read is running…" : busy === "sync" ? "Starting…" : "Read the site now"}
          </Button>
          <span className="text-sm text-muted-foreground">
            {status.scheduled ? `Also read automatically every ${status.intervalHours} hours.` : "Automatic reads are switched off on this server."}
          </span>
        </div>
      ) : null}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  missingChoices,
  parseCompanyId,
  settingsPayload,
  pickLabel,
  subIssuesFor,
  type AutotaskPicklists,
  type AutotaskSettings,
  type AutotaskStatus,
  type PickItem,
} from "@/lib/autotask-model";

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

function PickSelect({
  id,
  label,
  value,
  onChange,
  items,
  optional,
  hint,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  items: PickItem[] | undefined;
  optional?: boolean;
  hint?: string;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {items ? (
        <select id={id} className={selectClass} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">{optional ? "None (Autotask's own default)" : "Choose…"}</option>
          {value && !items.some((i) => i.value === value) ? <option value={value}>{pickLabel(items, value)}</option> : null}
          {items.map((i) => (
            <option key={i.value} value={i.value}>
              {i.label}
            </option>
          ))}
        </select>
      ) : (
        <p className="text-sm text-muted-foreground" id={id}>
          {value ? `Saved value ${value}` : "Not chosen"} (load Autotask&apos;s lists to change it)
        </p>
      )}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

/**
 * Choose the one Autotask company this instance opens tickets in, and every value a
 * ticket carries, from Autotask's own live lists. Nothing is pre-filled by DefendSec:
 * an Autotask taxonomy belongs to the client. The API user's secret is not entered
 * here at all: apid reads it from a file, so a credential never passes through a
 * browser.
 */
export function AutotaskPanel({ status, readOnly }: { status: AutotaskStatus; readOnly: boolean }) {
  const s = status.settings;
  const [f, setF] = useState<AutotaskSettings>(s);
  const [companyText, setCompanyText] = useState(s.companyId ? String(s.companyId) : "");
  const [search, setSearch] = useState("");
  const [found, setFound] = useState<{ id: number; name: string }[] | null>(null);
  const [lists, setLists] = useState<AutotaskPicklists | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const credsOk = status.credentials.configured;

  useEffect(() => {
    if (readOnly || !credsOk) return;
    let live = true;
    fetch("/api/autotask/picklists")
      .then(async (r) => {
        const j = await r.json();
        if (!r.ok) throw new Error(typeof j.error === "string" ? j.error : `Request failed (${r.status})`);
        return j as AutotaskPicklists;
      })
      .then((j) => live && setLists(j))
      .catch((e) => live && setListError(e instanceof Error ? e.message : "Autotask could not be read"));
    return () => {
      live = false;
    };
  }, [readOnly, credsOk]);

  function set<K extends keyof AutotaskSettings>(k: K, v: AutotaskSettings[K]) {
    setF((p) => ({ ...p, [k]: v }));
  }

  async function run(key: string, work: () => Promise<string>, reloadMs = 700) {
    setBusy(key);
    setFeedback(null);
    try {
      const message = await work();
      setFeedback({ kind: "ok", message });
      setTimeout(() => window.location.reload(), reloadMs);
    } catch (cause) {
      setFeedback({ kind: "error", message: cause instanceof Error ? cause.message : "Request failed" });
      setBusy(null);
    }
  }

  if (readOnly) {
    return <p className="text-sm text-muted-foreground">Choosing the company, changing how tickets look and running need an administrator.</p>;
  }

  const companyId = parseCompanyId(companyText);
  const body = (mode: "dry_run" | "live") => settingsPayload(f, companyId ?? 0, mode);
  const draftMissing = missingChoices({ ...f, companyId: companyId ?? 0 });
  const dirty = JSON.stringify({ ...f, companyId: companyId ?? 0, mode: s.mode }) !== JSON.stringify({ ...s, mode: s.mode });
  const subs = lists ? subIssuesFor(lists.subIssueTypes, f.issueType) : undefined;

  async function lookup() {
    setFeedback(null);
    try {
      const r = (await send(`/api/autotask/companies?q=${encodeURIComponent(search.trim())}`, "GET")) as { companies?: { id: number; name: string }[] };
      setFound(r.companies ?? []);
    } catch (cause) {
      setFeedback({ kind: "error", message: cause instanceof Error ? cause.message : "Request failed" });
    }
  }

  return (
    <div className="space-y-5" data-autotask-panel>
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
      {listError ? <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">Autotask&apos;s lists could not be loaded: {listError}</p> : null}

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="atk-user">API user (the name only)</Label>
          <Input id="atk-user" value={f.apiUser} onChange={(e) => set("apiUser", e.target.value)} placeholder="defendsec-api@example.com" />
          <p className="text-xs text-muted-foreground">The API-only user&apos;s name. Its secret and the integration code are files on the server, never typed here.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="atk-company">Autotask company (id)</Label>
          <Input id="atk-company" inputMode="numeric" value={companyText} onChange={(e) => setCompanyText(e.target.value)} placeholder="29683805" />
          <p className="text-xs text-muted-foreground">
            {lists?.company ? (
              <>
                {lists.company.name}
                {lists.company.active ? "" : " (not active in Autotask)"}. One DefendSec instance, one company.
              </>
            ) : lists?.companyProblem ? (
              lists.companyProblem
            ) : (
              "One DefendSec instance, one company. Look it up by name below."
            )}
          </p>
          <div className="flex gap-2">
            <Input aria-label="Search companies by name" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Part of the name" />
            <Button type="button" variant="outline" size="sm" disabled={!credsOk || search.trim().length < 2} onClick={lookup}>
              Search
            </Button>
          </div>
          {found ? (
            found.length === 0 ? (
              <p className="text-xs text-muted-foreground">No active company matches.</p>
            ) : (
              <ul className="space-y-1 text-sm" data-autotask-companies>
                {found.map((c) => (
                  <li key={c.id}>
                    <button type="button" className="underline" onClick={() => setCompanyText(String(c.id))}>
                      {c.name}
                    </button>{" "}
                    <span className="text-xs text-muted-foreground">id {c.id}</span>
                  </li>
                ))}
              </ul>
            )
          ) : null}
        </div>

        <PickSelect id="atk-queue" label="Queue" value={f.queueId} onChange={(v) => set("queueId", v)} items={lists?.queues} hint="A test queue first." />
        <PickSelect id="atk-status" label="Status of a new ticket" value={f.status} onChange={(v) => set("status", v)} items={lists?.statuses} />
        <PickSelect id="atk-prio-c" label="Priority for critical" value={f.priorityCritical} onChange={(v) => set("priorityCritical", v)} items={lists?.priorities} />
        <PickSelect id="atk-prio-h" label="Priority for high" value={f.priorityHigh} onChange={(v) => set("priorityHigh", v)} items={lists?.priorities} />
        <PickSelect id="atk-prio-m" label="Priority for medium" value={f.priorityMedium} onChange={(v) => set("priorityMedium", v)} items={lists?.priorities} />
        <PickSelect
          id="atk-source"
          label="Source"
          value={f.source}
          onChange={(v) => set("source", v)}
          items={lists?.sources}
          optional
          hint="Autotask suggests a source of its own for an integration, so its tickets can be told apart and routed by a workflow rule. Add one in Autotask first."
        />
        <PickSelect
          id="atk-issue"
          label="Issue type"
          value={f.issueType}
          onChange={(v) => {
            set("issueType", v);
            set("subIssueType", "");
          }}
          items={lists?.issueTypes}
          optional
          hint="Your own taxonomy decides where a security ticket belongs (for example Cybersecurity & Cloud)."
        />
        <PickSelect id="atk-sub" label="Sub-issue type" value={f.subIssueType} onChange={(v) => set("subIssueType", v)} items={subs} optional hint={f.issueType ? undefined : "Choose an issue type first."} />
        <PickSelect id="atk-note-type" label="Note type" value={f.noteType} onChange={(v) => set("noteType", v)} items={lists?.noteTypes} />
        <PickSelect id="atk-note-publish" label="Who may see a note" value={f.notePublish} onChange={(v) => set("notePublish", v)} items={lists?.notePublish} hint="Internal is the careful choice: a note names hosts." />
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="atk-min">Open a ticket for actions that are at least</Label>
          <select id="atk-min" className={selectClass} value={f.minUrgency} onChange={(e) => set("minUrgency", e.target.value as AutotaskSettings["minUrgency"])}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          <p className="text-xs text-muted-foreground">Critical: on the CISA KEV list, or a critical surface or identity finding. High: EPSS 0.10 or more, CVSS 7.0 or more, or past end of support. Low is never ticketed.</p>
        </div>
        <div className="space-y-1.5">
          <Label>Due in (days)</Label>
          <div className="grid grid-cols-3 gap-2">
            <Input aria-label="Due in days, critical" inputMode="numeric" value={String(f.dueDaysCritical)} onChange={(e) => set("dueDaysCritical", Number(e.target.value) || 0)} />
            <Input aria-label="Due in days, high" inputMode="numeric" value={String(f.dueDaysHigh)} onChange={(e) => set("dueDaysHigh", Number(e.target.value) || 0)} />
            <Input aria-label="Due in days, medium" inputMode="numeric" value={String(f.dueDaysMedium)} onChange={(e) => set("dueDaysMedium", Number(e.target.value) || 0)} />
          </div>
          <p className="text-xs text-muted-foreground">Critical, high, medium. Autotask needs a due date unless the ticket category sets one.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="atk-console">This console&apos;s address</Label>
          <Input id="atk-console" value={f.consoleUrl} onChange={(e) => set("consoleUrl", e.target.value)} placeholder="https://defendsec.example.net" />
          <p className="text-xs text-muted-foreground">Optional. Gives each ticket a link back to Fix this week.</p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="atk-max">Most new tickets per run</Label>
          <Input id="atk-max" inputMode="numeric" value={String(f.maxCreates)} onChange={(e) => set("maxCreates", Number(e.target.value) || 0)} />
          <p className="text-xs text-muted-foreground">The rest wait for the next run. A first run never floods the queue.</p>
        </div>
      </div>

      <div className="space-y-2">
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" checked={f.autoComplete} onChange={(e) => set("autoComplete", e.target.checked)} />
          <span>
            Complete a ticket when DefendSec sees every finding of its action fixed
            <span className="block text-xs text-muted-foreground">Off by default. Either way DefendSec adds a note with the evidence; with this off a person closes the ticket.</span>
          </span>
        </label>
        {f.autoComplete ? (
          <PickSelect id="atk-complete" label="Status that means completed" value={f.completeStatus} onChange={(v) => set("completeStatus", v)} items={lists?.statuses} />
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          disabled={busy !== null || (!companyId && companyText.trim() !== "")}
          onClick={() =>
            run("save", async () => {
              await send("/api/autotask/settings", "PUT", body(s.mode === "live" && !dirty ? "live" : "dry_run"));
              return "Saved. Run a dry run to see the tickets this would open.";
            })
          }
        >
          {busy === "save" ? "Saving…" : "Save settings"}
        </Button>
        <Button
          variant="outline"
          disabled={busy !== null || status.running || dirty || draftMissing.length > 0}
          title={dirty ? "Save the settings first: a dry run shows what the saved settings would do" : undefined}
          onClick={() =>
            run(
              "dry",
              async () => {
                await send("/api/autotask/run", "POST", { dryRun: true });
                return "Showing the tickets now (a dry run: nothing is sent). The page reloads in a moment.";
              },
              5000,
            )
          }
        >
          {status.running ? "A run is going…" : busy === "dry" ? "Starting…" : "Show me the tickets (dry run)"}
        </Button>
        {draftMissing.length > 0 ? <span className="text-xs text-muted-foreground">Still to choose: {draftMissing.join("; ")}.</span> : null}
        {s.mode === "live" && dirty ? (
          <span className="text-xs text-amber-700 dark:text-amber-400">
            Saving changes switches back to dry-run mode until a new dry run has shown them.
          </span>
        ) : null}
      </div>

      <div className="space-y-2 rounded-lg border p-3" data-autotask-live>
        <p className="text-sm font-medium">Open tickets for real</p>
        {s.mode === "live" ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-muted-foreground">
              Live. DefendSec reconciles the tickets {status.scheduled ? `every ${status.intervalHours} hours` : "when you ask (the schedule is off on this server)"}.
              {status.liveUnlocked ? "" : " The settings changed since the last dry run: a live run waits for a new one."}
            </p>
            <Button
              size="sm"
              disabled={busy !== null || status.running || !status.liveUnlocked}
              onClick={() =>
                run(
                  "live",
                  async () => {
                    await send("/api/autotask/run", "POST", { dryRun: false });
                    return "Reconciling now. The page reloads in a moment.";
                  },
                  6000,
                )
              }
            >
              Run now
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy !== null}
              onClick={() =>
                run("pause", async () => {
                  await send("/api/autotask/settings", "PUT", body("dry_run"));
                  return "Back to dry-run mode: no more tickets are opened.";
                })
              }
            >
              Stop opening tickets
            </Button>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-muted-foreground">
              Off. Tickets are opened only after a dry run for exactly these settings has shown them and read Autotask without a problem
              {status.liveUnlocked ? " (it has)" : ""}. Use a test company or queue first.
            </p>
            <Button
              size="sm"
              disabled={busy !== null || !status.liveUnlocked || dirty}
              onClick={() => {
                if (!window.confirm("Open tickets in the Autotask company chosen above? Look at the dry run first: this sends exactly those tickets.")) return;
                void run("golive", async () => {
                  await send("/api/autotask/settings", "PUT", body("live"));
                  return "Live. The next scheduled run (or Run now) opens the tickets.";
                });
              }}
            >
              Go live
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

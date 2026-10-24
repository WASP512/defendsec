"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { kindLabel, splitSelectors, validateAssetForm, type AssetKind, type SurfaceAsset } from "@/lib/surface-model";

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

function when(iso: string | null) {
  if (!iso) return "never";
  return new Date(iso).toLocaleString();
}

export function AssetsPanel({ assets, readOnly }: { assets: SurfaceAsset[]; readOnly: boolean }) {
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function run(key: string, work: () => Promise<string>) {
    setBusy(key);
    setFeedback(null);
    try {
      const message = await work();
      setFeedback({ kind: "ok", message });
      // The server renders the lists; reload to show the new state.
      setTimeout(() => window.location.reload(), 600);
    } catch (cause) {
      setFeedback({ kind: "error", message: cause instanceof Error ? cause.message : "Request failed" });
      setBusy(null);
    }
  }

  async function scan(assetId?: number) {
    const out = (await send("/api/surface/scan", "POST", assetId ? { assetId } : {})) as {
      scans?: { value: string; status: string; reason?: string; summary?: { open: number; new: number; resolved: number } }[];
    };
    const scans = out.scans ?? [];
    const failed = scans.filter((s) => s.status === "failed");
    if (failed.length > 0) throw new Error(failed.map((s) => `${s.value}: ${s.reason ?? "scan failed"}`).join("; "));
    const done = scans.filter((s) => s.status === "done");
    const skipped = scans.length - done.length;
    return `Scanned ${done.length} asset${done.length === 1 ? "" : "s"}${skipped ? `, ${skipped} skipped (not confirmed, already scanning, or scanned a moment ago)` : ""}.`;
  }

  const confirmed = assets.filter((a) => a.authorised).length;

  return (
    <div className="space-y-6">
      {!readOnly ? <AddAsset onAdded={(m) => run("add", async () => m)} onError={(m) => setFeedback({ kind: "error", message: m })} /> : null}

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

      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-medium">Declared assets</h2>
        {!readOnly && confirmed > 0 ? (
          <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run("all", () => scan())}>
            {busy === "all" ? "Scanning…" : `Scan all confirmed (${confirmed})`}
          </Button>
        ) : null}
      </div>

      <ul className="space-y-2">
        {assets.map((a) => (
          <li key={a.id} className="flex flex-col gap-3 rounded-xl border bg-card p-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium break-all">{a.value}</span>
                <Badge variant="outline">{kindLabel(a.kind)}</Badge>
                {a.authorised ? <Badge>Confirmed</Badge> : <Badge variant="destructive">Not confirmed</Badge>}
                {a.sharedHosting ? <Badge variant="secondary">Shared hosting</Badge> : null}
                {a.mailHost ? <Badge variant="secondary">Mail host</Badge> : null}
              </div>
              {a.label ? <div className="text-sm text-muted-foreground">{a.label}</div> : null}
              <div className="text-xs text-muted-foreground">
                {a.authorised
                  ? `Authorised to test: confirmed by ${a.authorisedBy || "unknown"} on ${when(a.authorisedAt)}.`
                  : "Not scanned until someone confirms they are authorised to test it."}{" "}
                Last scan: {when(a.lastScanAt)}.
                {a.dkimSelectors.length ? ` DKIM selectors: ${a.dkimSelectors.join(", ")}.` : ""}
              </div>
            </div>
            {!readOnly ? (
              <div className="flex shrink-0 flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy !== null || !a.authorised}
                  title={a.authorised ? undefined : "Confirm authorisation first"}
                  onClick={() => run(`scan-${a.id}`, () => scan(a.id))}
                >
                  {busy === `scan-${a.id}` ? "Scanning…" : "Scan now"}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy !== null}
                  onClick={() =>
                    run(`auth-${a.id}`, async () => {
                      await send(`/api/assets/${a.id}`, "POST", { authorised: !a.authorised });
                      return a.authorised ? `Withdrew the confirmation for ${a.value}; it will not be scanned.` : `Confirmed ${a.value}.`;
                    })
                  }
                >
                  {a.authorised ? "Withdraw confirmation" : "I am authorised: confirm"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy !== null}
                  onClick={() => {
                    if (!window.confirm(`Remove ${a.value}? Scanning stops. Its findings are kept as evidence.`)) return;
                    void run(`rm-${a.id}`, async () => {
                      await send(`/api/assets/${a.id}`, "DELETE");
                      return `Removed ${a.value}.`;
                    });
                  }}
                >
                  Remove
                </Button>
              </div>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

function AddAsset({ onAdded, onError }: { onAdded: (message: string) => void; onError: (message: string) => void }) {
  const [kind, setKind] = useState<AssetKind>("domain");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [selectors, setSelectors] = useState("");
  const [shared, setShared] = useState(false);
  const [mail, setMail] = useState(false);
  const [authorised, setAuthorised] = useState(false);
  const [pending, setPending] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const problem = validateAssetForm({ kind, value, dkimSelectors: selectors });
    if (problem) {
      onError(problem);
      return;
    }
    setPending(true);
    try {
      await send("/api/assets", "POST", {
        kind,
        value: value.trim(),
        label: label.trim(),
        dkimSelectors: kind === "domain" ? splitSelectors(selectors) : [],
        sharedHosting: kind === "ip" ? shared : false,
        mailHost: kind === "ip" ? mail : false,
        authorised,
      });
      setValue("");
      setLabel("");
      setSelectors("");
      onAdded(
        authorised
          ? `Declared ${value.trim()} and confirmed authorisation. Use Scan now to check it.`
          : `Declared ${value.trim()}. It will not be scanned until you confirm you are authorised to test it.`,
      );
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Request failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 rounded-xl border bg-card p-4">
      <h2 className="text-lg font-medium">Declare an asset</h2>
      <p className="text-sm text-muted-foreground">
        Only assets listed here are ever checked, and only after authorisation is confirmed. The scan reads DNS, makes TLS
        handshakes, fetches the MTA-STS policy and tries TCP connections. It never logs in and never sends an exploit.
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="asset-kind">Type</Label>
          <select id="asset-kind" className={selectClass} value={kind} onChange={(e) => setKind(e.target.value as AssetKind)}>
            <option value="domain">Domain (email authentication, DNS, TLS)</option>
            <option value="hostname">Hostname (DNS, TLS)</option>
            <option value="ip">IP address (open ports)</option>
          </select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="asset-value">{kind === "ip" ? "IP address" : kind === "hostname" ? "Hostname" : "Domain"}</Label>
          <Input
            id="asset-value"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={kind === "ip" ? "203.0.113.10" : kind === "hostname" ? "www.example.com" : "example.com"}
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="asset-label">Note (optional)</Label>
          <Input id="asset-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Main website" />
        </div>
        {kind === "domain" ? (
          <div className="space-y-1.5">
            <Label htmlFor="asset-selectors">DKIM selectors (optional)</Label>
            <Input
              id="asset-selectors"
              value={selectors}
              onChange={(e) => setSelectors(e.target.value)}
              placeholder="google, selector1"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Selectors cannot be listed from DNS. Common ones are tried; add yours so a missing key is noticed.
            </p>
          </div>
        ) : null}
      </div>
      {kind === "ip" ? (
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={shared} onChange={(e) => setShared(e.target.checked)} />
            Shared hosting or CDN address (results describe the provider, not you)
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={mail} onChange={(e) => setMail(e.target.checked)} />
            Runs a mail server (25, 110 and 143 are expected)
          </label>
        </div>
      ) : null}
      <label className="flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
        <input className="mt-1" type="checkbox" checked={authorised} onChange={(e) => setAuthorised(e.target.checked)} />
        <span>
          <strong>I am authorised to test this asset.</strong> I own it, or its owner has agreed in writing that it may be
          scanned. Without this the asset is saved but never scanned.
        </span>
      </label>
      <Button type="submit" disabled={pending}>
        {pending ? "Saving…" : "Declare asset"}
      </Button>
    </form>
  );
}

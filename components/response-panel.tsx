"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Activity, ShieldAlert, Terminal, Upload } from "lucide-react";
import type { CommandRecord } from "@/lib/commands";
import { relativeTime } from "@/lib/format";

const LIVE_QUERIES = [
  "processes",
  "listening_ports",
  "users",
  "logged_in_users",
  "crontab",
  "systemd_units",
  "mounts",
  "os_info",
] as const;

type SavedQuery = {
  id: string;
  name: string;
  query: string;
};

type AgentRelease = {
  version: string;
  url: string;
  sha256: string;
  notes?: string;
};

function liveQueryFromPayload(payload: string): string {
  try {
    const parsed = JSON.parse(payload) as { query?: string };
    return parsed.query ?? "";
  } catch {
    return "";
  }
}

function CommandOutput({ item }: { item: CommandRecord }) {
  if (item.type !== "live_query" || !item.message) {
    return (
      <p className="text-muted-foreground">
        {item.message || item.payload} · {relativeTime(item.updatedAt || item.createdAt)}
      </p>
    );
  }
  const lines = item.message.split("\n");
  const header = lines[0] ?? "";
  const rows = lines.slice(1).filter(Boolean);
  const cols = header.split("\t");
  if (rows.length > 0 && cols.length > 1) {
    return (
      <div className="mt-2 space-y-2">
        <p className="text-xs text-muted-foreground">
          {liveQueryFromPayload(item.payload) || "live_query"} · {relativeTime(item.updatedAt || item.createdAt)}
        </p>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/50">
              <tr>
                {cols.map((col) => (
                  <th key={col} className="px-2 py-1 font-medium">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, 50).map((row, index) => {
                const cells = row.split("\t");
                return (
                  <tr key={index} className="border-t">
                    {cells.map((cell, cellIndex) => (
                      <td key={cellIndex} className="px-2 py-1 font-mono">
                        {cell}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {rows.length > 50 ? (
            <p className="px-2 py-1 text-xs text-muted-foreground">… {rows.length - 50} more rows</p>
          ) : null}
        </div>
      </div>
    );
  }
  return (
    <div className="mt-2 space-y-1">
      <p className="text-xs text-muted-foreground">
        {liveQueryFromPayload(item.payload) || "live_query"} · {relativeTime(item.updatedAt || item.createdAt)}
      </p>
      <pre className="max-h-64 overflow-auto rounded-md border bg-muted/30 p-2 text-xs">{item.message}</pre>
    </div>
  );
}

export function ResponsePanel({
  mtlsDeviceId,
  isolated,
  commands,
  readOnly,
}: {
  mtlsDeviceId: string;
  isolated: boolean;
  commands: CommandRecord[];
  readOnly?: boolean;
}) {
  const [pending, setPending] = useState<string>("");
  const [confirmAction, setConfirmAction] = useState<"isolate" | "revoke" | null>(null);
  const [error, setError] = useState("");
  const [killName, setKillName] = useState("");
  const [query, setQuery] = useState<string>("processes");
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
  const [saveName, setSaveName] = useState("");
  const [release, setRelease] = useState<AgentRelease | null>(null);
  const [updateVersion, setUpdateVersion] = useState("");
  const [updateURL, setUpdateURL] = useState("");
  const [updateSHA256, setUpdateSHA256] = useState("");

  useEffect(() => {
    if (!mtlsDeviceId) return;
    void fetch("/api/saved-queries")
      .then((response) => response.json())
      .then((data: { queries?: SavedQuery[] }) => setSavedQueries(data.queries ?? []))
      .catch(() => setSavedQueries([]));
    void fetch("/api/agent-releases?channel=stable")
      .then((response) => (response.ok ? response.json() : null))
      .then((data: AgentRelease | null) => {
        if (data?.version) {
          setRelease(data);
          setUpdateVersion(data.version);
          setUpdateURL(data.url);
          setUpdateSHA256(data.sha256);
        }
      })
      .catch(() => setRelease(null));
  }, [mtlsDeviceId]);

  if (!mtlsDeviceId) {
    return (
      <div className="rounded-xl border border-dashed p-6">
        <p className="font-medium">No mTLS agent on this host</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Signed isolate / kill requires <code className="text-foreground">defendsec-agentd</code>. The
          Python inventory agent cannot receive control commands.
        </p>
      </div>
    );
  }

  async function send(type: string, payload: Record<string, string> = {}) {
    setPending(type);
    setError("");
    try {
      const response = await fetch(`/api/devices/${mtlsDeviceId}/command`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, payload }),
      });
      const data = (await response.json()) as { error?: string; message?: string };
      if (!response.ok) {
        throw new Error(data.error ?? `Request failed (${response.status})`);
      }
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
      setPending("");
    }
  }

  async function saveQuery() {
    if (!saveName.trim()) return;
    setPending("save_query");
    setError("");
    try {
      const response = await fetch("/api/saved-queries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: saveName.trim(), query }),
      });
      const data = (await response.json()) as SavedQuery & { error?: string };
      if (!response.ok) {
        throw new Error(data.error ?? "Could not save query");
      }
      setSavedQueries((prev) => [{ id: data.id, name: data.name, query: data.query }, ...prev]);
      setSaveName("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    } finally {
      setPending("");
    }
  }

  async function revokeDevice() {
    setPending("revoke");
    setError("");
    try {
      const response = await fetch(`/api/devices/${mtlsDeviceId}/revoke`, { method: "POST" });
      const data = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(data.error ?? `Revoke failed (${response.status})`);
      }
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
      setPending("");
    }
  }

  if (readOnly) {
    return (
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Signed in with a viewer token. Response commands and certificate revoke require an admin
          token.
        </p>
        {commands.length === 0 ? (
          <p className="text-sm text-muted-foreground">No signed commands yet for this agent.</p>
        ) : (
          <ul className="divide-y rounded-xl border">
            {commands.map((item) => (
              <li key={item.id} className="px-4 py-3 text-sm">
                <p className="font-medium">
                  {item.type} · {item.status}
                  {item.accepted ? " · accepted" : ""}
                </p>
                <CommandOutput item={item} />
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="size-4" />
            Host containment
          </CardTitle>
          <CardDescription>
            Commands are Ed25519-signed by defendsec-apid and verified by this agent.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
        <Button
          variant={isolated ? "outline" : "destructive"}
          size="sm"
          disabled={Boolean(pending) || isolated}
          onClick={() => setConfirmAction("isolate")}
        >
          {pending === "isolate" ? "Sending…" : isolated ? "Already isolated" : "Isolate host"}
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={Boolean(pending) || !isolated}
          onClick={() => send("release")}
        >
          {pending === "release" ? "Sending…" : "Release isolation"}
        </Button>
        <Button variant="outline" size="sm" disabled={Boolean(pending)} onClick={() => setConfirmAction("revoke")}>
          {pending === "revoke" ? "Revoking…" : "Revoke certificate"}
        </Button>
        </CardContent>
      </Card>
      <form
        className="rounded-xl border bg-card p-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (!killName.trim()) return;
          void send("kill_process", { name: killName.trim() });
        }}
      >
        <div className="mb-3">
          <p className="flex items-center gap-2 font-medium"><Terminal className="size-4" /> Process response</p>
          <p className="mt-1 text-sm text-muted-foreground">Send SIGTERM to an allowlisted process name.</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1 space-y-1">
            <Label htmlFor="kill-name">Process name</Label>
            <Input
              id="kill-name"
              name="name"
              placeholder="sleep"
              value={killName}
              onChange={(event) => setKillName(event.target.value)}
              autoComplete="off"
            />
          </div>
          <Button type="submit" variant="destructive" size="sm" disabled={Boolean(pending) || !killName.trim()}>
            {pending === "kill_process" ? "Sending…" : "Send SIGTERM"}
          </Button>
        </div>
      </form>
      <form
        className="space-y-3 rounded-xl border bg-card p-4"
        onSubmit={(event) => {
          event.preventDefault();
          void send("live_query", { query });
        }}
      >
        <div>
          <p className="flex items-center gap-2 font-medium"><Activity className="size-4" /> Live query</p>
          <p className="mt-1 text-sm text-muted-foreground">Run an allowlisted host snapshot and keep reusable query presets.</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1 space-y-1">
            <Label htmlFor="live-query">Live query</Label>
            <Select
              value={query}
              onValueChange={(value) => setQuery(String(value))}
            >
              <SelectTrigger id="live-query" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LIVE_QUERIES.map((item) => (
                  <SelectItem key={item} value={item}>{item}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {savedQueries.length > 0 ? (
            <div className="min-w-0 flex-1 space-y-1">
              <Label htmlFor="saved-query">Saved queries</Label>
              <Select
                onValueChange={(value) => {
                  const picked = savedQueries.find((item) => item.id === String(value));
                  if (picked) setQuery(picked.query);
                }}
              >
                <SelectTrigger id="saved-query" className="w-full">
                  <SelectValue placeholder="Load saved…" />
                </SelectTrigger>
                <SelectContent>
                  {savedQueries.map((item) => (
                    <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : null}
          <Button type="submit" variant="outline" size="sm" disabled={Boolean(pending)}>
            {pending === "live_query" ? "Sending…" : "Run query"}
          </Button>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1 space-y-1">
            <Label htmlFor="save-query-name">Save current query as</Label>
            <Input
              id="save-query-name"
              placeholder="SSH users audit"
              value={saveName}
              onChange={(event) => setSaveName(event.target.value)}
              autoComplete="off"
            />
          </div>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            disabled={Boolean(pending) || !saveName.trim()}
            onClick={() => void saveQuery()}
          >
            {pending === "save_query" ? "Saving…" : "Save query"}
          </Button>
        </div>
      </form>
      <form
        className="space-y-3 rounded-xl border bg-card p-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (!updateVersion.trim() || !updateURL.trim() || !updateSHA256.trim()) return;
          void send("agent_update", {
            version: updateVersion.trim(),
            url: updateURL.trim(),
            sha256: updateSHA256.trim(),
          });
        }}
      >
        <div>
          <p className="flex items-center gap-2 font-medium"><Upload className="size-4" /> Push agent update</p>
          <p className="mt-1 text-sm text-muted-foreground">Download, verify SHA256, replace the binary, and let systemd restart it.</p>
        </div>
        {release ? (
          <p className="text-xs text-muted-foreground">
            Latest stable release: {release.version}
            {release.notes ? ` — ${release.notes}` : ""}
          </p>
        ) : null}
        <div className="grid gap-2 sm:grid-cols-3">
          <div className="space-y-1">
            <Label htmlFor="update-version">Version</Label>
            <Input
              id="update-version"
              value={updateVersion}
              onChange={(event) => setUpdateVersion(event.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-1 sm:col-span-2">
            <Label htmlFor="update-url">Download URL</Label>
            <Input
              id="update-url"
              value={updateURL}
              onChange={(event) => setUpdateURL(event.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="space-y-1 sm:col-span-3">
            <Label htmlFor="update-sha256">SHA256</Label>
            <Input
              id="update-sha256"
              value={updateSHA256}
              onChange={(event) => setUpdateSHA256(event.target.value)}
              className="font-mono text-xs"
              autoComplete="off"
            />
          </div>
        </div>
        <Button
          type="submit"
          variant="outline"
          size="sm"
          disabled={
            Boolean(pending) || !updateVersion.trim() || !updateURL.trim() || !updateSHA256.trim()
          }
        >
          {pending === "agent_update" ? "Pushing…" : "Push agent update"}
        </Button>
      </form>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <div className="flex items-center justify-between">
        <h3 className="font-medium">Command history</h3>
        <span className="text-xs text-muted-foreground">{commands.length} command{commands.length === 1 ? "" : "s"}</span>
      </div>
      {commands.length === 0 ? (
        <p className="rounded-xl border border-dashed p-6 text-sm text-muted-foreground">No signed commands yet for this agent.</p>
      ) : (
        <ul className="divide-y rounded-xl border">
          {commands.map((item) => (
            <li key={item.id} className="px-4 py-3 text-sm">
              <p className="font-medium">
                {item.type} · {item.status}
                {item.accepted ? " · accepted" : ""}
              </p>
              <CommandOutput item={item} />
            </li>
          ))}
        </ul>
      )}
      <AlertDialog open={confirmAction !== null} onOpenChange={(open) => !open && setConfirmAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogMedia>
              <ShieldAlert className="text-destructive" />
            </AlertDialogMedia>
            <AlertDialogTitle>
              {confirmAction === "isolate" ? "Isolate this host?" : "Revoke this certificate?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirmAction === "isolate"
                ? "The agent will restrict network access until you explicitly release isolation."
                : "The agent will disconnect and must re-enroll before it can report inventory or receive commands."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                const action = confirmAction;
                setConfirmAction(null);
                if (action === "isolate") void send("isolate");
                if (action === "revoke") void revokeDevice();
              }}
            >
              {confirmAction === "isolate" ? "Isolate host" : "Revoke certificate"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
    if (!window.confirm("Revoke this agent certificate? The host must re-enroll to connect again.")) {
      return;
    }
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
      <p className="text-sm text-muted-foreground">
        Commands are Ed25519-signed by defendsec-apid and verified on the agent. Live query runs an
        allowlisted host snapshot. Agent update downloads, verifies sha256, and replaces the running
        binary (systemd should restart the agent on exit).
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          variant={isolated ? "outline" : "destructive"}
          size="sm"
          disabled={Boolean(pending) || isolated}
          onClick={() => send("isolate")}
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
        <Button variant="outline" size="sm" disabled={Boolean(pending)} onClick={() => void revokeDevice()}>
          {pending === "revoke" ? "Revoking…" : "Revoke certificate"}
        </Button>
      </div>
      <form
        className="flex flex-col gap-2 sm:flex-row sm:items-end"
        onSubmit={(event) => {
          event.preventDefault();
          if (!killName.trim()) return;
          void send("kill_process", { name: killName.trim() });
        }}
      >
        <div className="min-w-0 flex-1 space-y-1">
          <Label htmlFor="kill-name">Signal process by name</Label>
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
      </form>
      <form
        className="space-y-2"
        onSubmit={(event) => {
          event.preventDefault();
          void send("live_query", { query });
        }}
      >
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <div className="min-w-0 flex-1 space-y-1">
            <Label htmlFor="live-query">Live query</Label>
            <select
              id="live-query"
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            >
              {LIVE_QUERIES.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
          {savedQueries.length > 0 ? (
            <div className="min-w-0 flex-1 space-y-1">
              <Label htmlFor="saved-query">Saved queries</Label>
              <select
                id="saved-query"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                defaultValue=""
                onChange={(event) => {
                  const picked = savedQueries.find((item) => item.id === event.target.value);
                  if (picked) setQuery(picked.query);
                }}
              >
                <option value="" disabled>
                  Load saved…
                </option>
                {savedQueries.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
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
        className="space-y-2 rounded-xl border p-4"
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
        <p className="text-sm font-medium">Push agent update</p>
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

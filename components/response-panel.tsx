"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { CommandRecord } from "@/lib/commands";
import { relativeTime } from "@/lib/format";

export function ResponsePanel({
  mtlsDeviceId,
  isolated,
  commands,
}: {
  mtlsDeviceId: string;
  isolated: boolean;
  commands: CommandRecord[];
}) {
  const [pending, setPending] = useState<string>("");
  const [error, setError] = useState("");
  const [killName, setKillName] = useState("");

  if (!mtlsDeviceId) {
    return (
      <div className="rounded-xl border border-dashed p-6">
        <p className="font-medium">No mTLS agent on this host</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Signed isolate / kill requires <code className="text-foreground">keel-agentd</code>. The
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

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Commands are Ed25519-signed by keel-apid and verified on the agent. Unsigned payloads are
        rejected. Isolation is a host flag (network drop only if the agent is root with{" "}
        <code className="text-foreground">KEEL_ISOLATE_NET=1</code>). Kill matches{" "}
        <code className="text-foreground">/proc/*/comm</code> and will not signal protected names
        such as systemd, sshd, or keel-agentd.
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
              <p className="text-muted-foreground">
                {item.message || item.payload} · {relativeTime(item.updatedAt || item.createdAt)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

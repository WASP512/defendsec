"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function EnrollPanel({
  enrollSecret,
  serverUrl,
}: {
  enrollSecret: string;
  serverUrl: string;
}) {
  const [secret, setSecret] = useState(enrollSecret);
  const [copied, setCopied] = useState<"secret" | "install" | "go" | "py" | null>(null);
  const [rotateError, setRotateError] = useState("");
  const [rotating, setRotating] = useState(false);

  const host = (() => {
    try {
      return new URL(serverUrl).hostname || "127.0.0.1";
    } catch {
      return "127.0.0.1";
    }
  })();

  const downloadBase = (() => {
    try {
      const u = new URL(serverUrl);
      return `${u.protocol}//${u.host}/downloads`;
    } catch {
      return `http://${host}:47261/downloads`;
    }
  })();

  const installCommand = [
    `curl -fsSL "${downloadBase}/install-agent.sh" | sudo bash -s -- \\`,
    `  --server-http https://${host}:47262 \\`,
    `  --server-grpc ${host}:47263 \\`,
    `  --tls-server-name ${host} \\`,
    `  --enroll-secret ${secret} \\`,
    `  --download-base "${downloadBase}"`,
  ].join("\n");

  const goCommand = [
    `./bin/defendsec-agentd \\`,
    `  --server-http https://${host}:47262 \\`,
    `  --server-grpc ${host}:47263 \\`,
    `  --tls-server-name ${host} \\`,
    `  --enroll-secret ${secret} \\`,
    `  --state-dir data/agent-mtls`,
  ].join("\n");

  const pyCommand = `python3 agent/defendsec-agent.py --server ${serverUrl} --enroll-secret ${secret}`;

  async function rotate() {
    setRotateError("");
    setRotating(true);
    try {
      const res = await fetch("/api/enroll-secret", { method: "POST" });
      const data = (await res.json()) as { enrollSecret?: string; error?: string };
      if (!res.ok || !data.enrollSecret) {
        throw new Error(data.error || `Rotation failed (${res.status})`);
      }
      setSecret(data.enrollSecret);
    } catch (error) {
      setRotateError(error instanceof Error ? error.message : "Rotation failed");
    } finally {
      setRotating(false);
    }
  }

  async function copy(kind: "secret" | "install" | "go" | "py", value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(kind);
    setTimeout(() => setCopied(null), 1500);
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="secret">Enroll secret</Label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input id="secret" readOnly value={secret} className="font-mono" />
          <div className="flex gap-2">
            <Button type="button" variant="outline" onClick={() => copy("secret", secret)}>
              {copied === "secret" ? "Copied" : "Copy"}
            </Button>
            <Button type="button" variant="outline" disabled={rotating} onClick={rotate}>
              {rotating ? "Rotating…" : "Rotate"}
            </Button>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          Anyone with this secret can enroll a host. Rotate it if it leaks; existing agents keep
          their node keys.
        </p>
        {rotateError ? <p className="text-sm text-destructive">{rotateError}</p> : null}
      </div>

      <div className="space-y-2">
        <Label htmlFor="install-cmd">Agent install (recommended — curl download + systemd)</Label>
        <textarea
          id="install-cmd"
          readOnly
          rows={7}
          className="w-full rounded-lg border bg-muted/40 p-3 font-mono text-sm"
          value={installCommand}
        />
        <Button type="button" onClick={() => copy("install", installCommand)}>
          {copied === "install" ? "Copied command" : "Copy install command"}
        </Button>
        <p className="mt-1 text-sm text-muted-foreground">
          Run this on each host you want to watch — not on the Proxmox server. It downloads the
          agent from this console and enables systemd.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="go-cmd">Go agent (manual binary)</Label>
        <textarea
          id="go-cmd"
          readOnly
          rows={6}
          className="w-full rounded-lg border bg-muted/40 p-3 font-mono text-sm"
          value={goCommand}
        />
        <Button type="button" variant="outline" onClick={() => copy("go", goCommand)}>
          {copied === "go" ? "Copied command" : "Copy Go command"}
        </Button>
        <p className="mt-1 text-sm text-muted-foreground">
          Build with <code className="text-foreground">make agent</code> (or copy{" "}
          <code className="text-foreground">bin/defendsec-agentd</code>). On Fedora, use your LAN
          hostname/IP and match <code className="text-foreground">--tls-server-name</code> to a
          certificate SAN. Developer lab notes: <code className="text-foreground">docs/FEDORA.md</code>.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="py-cmd">Python agent (inventory check-in only)</Label>
        <textarea
          id="py-cmd"
          readOnly
          rows={2}
          className="w-full rounded-lg border bg-muted/40 p-3 font-mono text-sm"
          value={pyCommand}
        />
        <Button type="button" variant="outline" onClick={() => copy("py", pyCommand)}>
          {copied === "py" ? "Copied command" : "Copy Python command"}
        </Button>
        <p className="mt-1 text-sm text-muted-foreground">
          Standard library only. No signed isolate/kill/live query — use the Go agent for response
          actions.
        </p>
      </div>
    </div>
  );
}

"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Check, Copy, Terminal } from "lucide-react";

export function EnrollPanel({
  enrollSecret,
  serverUrl,
}: {
  enrollSecret: string;
  serverUrl: string;
}) {
  const [secret, setSecret] = useState(enrollSecret);
  const [snippetTab, setSnippetTab] = useState("install");
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
    `echo "Downloading DefendSec agent installer…" && \\`,
    `  curl -fL --progress-bar "${downloadBase}/install-agent.sh" -o /tmp/install-agent.sh && \\`,
    `  sudo bash /tmp/install-agent.sh \\`,
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

      <div className="space-y-3">
        <div>
          <h2 className="font-medium">Install an agent</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Choose the deployment method that matches the target host.
          </p>
        </div>
        <Tabs
          value={snippetTab}
          onValueChange={(value) => setSnippetTab(String(value))}
          className="overflow-hidden rounded-xl border bg-card"
        >
          <div className="flex flex-col gap-3 border-b bg-muted/30 p-3 sm:flex-row sm:items-center sm:justify-between">
            <TabsList>
              <TabsTrigger value="install">Agent install</TabsTrigger>
              <TabsTrigger value="go">Go binary</TabsTrigger>
              <TabsTrigger value="python">Python</TabsTrigger>
            </TabsList>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Terminal className="size-3.5" />
              Run on the target host
            </div>
          </div>
          {[
            {
              value: "install",
              kind: "install" as const,
              command: installCommand,
              description: "Recommended. Downloads the agent, installs it, and enables systemd.",
            },
            {
              value: "go",
              kind: "go" as const,
              command: goCommand,
              description: "Manual binary. Supports signed response, live queries, and agent updates.",
            },
            {
              value: "python",
              kind: "py" as const,
              command: pyCommand,
              description: "Inventory check-in only. Signed response actions require the Go agent.",
            },
          ].map((snippet) => (
            <TabsContent key={snippet.value} value={snippet.value} className="m-0">
              <div className="flex items-center justify-between border-b px-4 py-2">
                <span className="text-xs font-medium text-muted-foreground">shell</span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => copy(snippet.kind, snippet.command)}
                >
                  {copied === snippet.kind ? <Check className="size-4" /> : <Copy className="size-4" />}
                  {copied === snippet.kind ? "Copied" : "Copy"}
                </Button>
              </div>
              <pre className="max-h-80 overflow-auto bg-muted/20 p-4 text-sm">
                <code>{snippet.command}</code>
              </pre>
              <p className="border-t px-4 py-3 text-sm text-muted-foreground">
                {snippet.description}
              </p>
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </div>
  );
}

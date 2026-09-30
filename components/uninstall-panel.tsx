"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Check, Copy } from "lucide-react";
import { agentPlatform, uninstallCommand } from "@/lib/agent-commands";

// The command that removes the agent from this host. Shown rather than run:
// uninstalling is done on the host, by someone with root there, so a
// compromised console cannot remove agents from the fleet.
export function UninstallPanel({
  platform,
  downloadBase,
}: {
  platform: string;
  downloadBase: string;
}) {
  const [purge, setPurge] = useState(false);
  const [copied, setCopied] = useState(false);
  const family = agentPlatform(platform);
  if (!family) {
    return (
      <p className="text-sm text-muted-foreground">
        This host has not reported a platform DefendSec has an uninstaller for.
      </p>
    );
  }
  const command = uninstallCommand(family, downloadBase, purge);
  return (
    <div className="overflow-hidden rounded-xl border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={purge} onChange={(e) => setPurge(e.target.checked)} />
          Also delete the agent&apos;s certificate and key
        </label>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={async () => {
            await navigator.clipboard.writeText(command);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre className="max-h-60 overflow-auto bg-muted/20 p-4 text-sm">
        <code>{command}</code>
      </pre>
      <p className="border-t px-4 py-3 text-sm text-muted-foreground">
        Run on the host{family === "windows" ? " in Windows PowerShell as administrator" : " with sudo"}. It stops and
        removes the service and binary. The host then shows as offline here until it is removed from the fleet.
      </p>
    </div>
  );
}

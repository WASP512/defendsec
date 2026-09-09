"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
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
  const router = useRouter();
  const [secret, setSecret] = useState(enrollSecret);
  const [copied, setCopied] = useState<"secret" | "cmd" | null>(null);

  const command = `python3 agent/keel-agent.py --server ${serverUrl} --enroll-secret ${secret}`;

  async function rotate() {
    const res = await fetch("/api/enroll-secret", { method: "POST" });
    const data = (await res.json()) as { enrollSecret: string };
    setSecret(data.enrollSecret);
    router.refresh();
  }

  async function copy(kind: "secret" | "cmd", value: string) {
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
            <Button type="button" variant="outline" onClick={rotate}>
              Rotate
            </Button>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          Anyone with this secret can enroll a host. Rotate it if it leaks; existing agents keep
          their node keys.
        </p>
      </div>
      <div className="space-y-2">
        <Label htmlFor="cmd">Install on a host</Label>
        <textarea
          id="cmd"
          readOnly
          rows={3}
          className="w-full rounded-lg border bg-muted/40 p-3 font-mono text-sm"
          value={command}
        />
        <Button type="button" onClick={() => copy("cmd", command)}>
          {copied === "cmd" ? "Copied command" : "Copy command"}
        </Button>
        <p className="mt-1 text-muted-foreground">
          Python 3 standard library only. The agent enrolls, then checks in every 30 seconds with
          OS, software versions, pending patches, and hashes of watched system files.
        </p>
      </div>
    </div>
  );
}

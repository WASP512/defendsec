"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";

export function AcceptBaseline({ deviceId }: { deviceId: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    setPending(true);
    setError("");
    try {
      const response = await fetch(`/api/devices/${deviceId}/baseline`, { method: "POST" });
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
      setPending(false);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button variant="outline" size="sm" disabled={pending} onClick={save}>
        {pending ? "Saving…" : "Accept current as baseline"}
      </Button>
      {error ? <span className="text-xs text-destructive">{error}</span> : null}
    </div>
  );
}

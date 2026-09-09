"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { FindingStatus } from "@/lib/types";

export function FindingActions({ findingKey, status }: { findingKey: string; status: FindingStatus }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const next = status === "open" ? "acknowledged" : "open";

  async function save() {
    setPending(true);
    setError("");
    try {
      const response = await fetch("/api/findings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: findingKey, status: next }),
      });
      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
      }
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
      setPending(false);
    }
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button variant="outline" size="sm" disabled={pending} onClick={save}>
        {pending ? "Saving…" : status === "open" ? "Acknowledge" : "Reopen"}
      </Button>
      {error ? <span className="text-xs text-destructive">{error}</span> : null}
    </div>
  );
}

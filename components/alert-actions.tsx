"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { AlertStatus } from "@/lib/alerts";

export function AlertActions({
  alertId,
  status,
  readOnly,
}: {
  alertId: string;
  status: AlertStatus;
  readOnly?: boolean;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function setStatus(next: AlertStatus) {
    setPending(true);
    setError("");
    try {
      const response = await fetch("/api/alerts", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: alertId, status: next }),
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

  if (readOnly) {
    return <span className="text-xs text-muted-foreground">Viewer (read-only)</span>;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {status === "open" ? (
        <Button variant="outline" size="sm" disabled={pending} onClick={() => setStatus("acknowledged")}>
          Acknowledge
        </Button>
      ) : null}
      {status === "open" || status === "acknowledged" ? (
        <Button variant="outline" size="sm" disabled={pending} onClick={() => setStatus("resolved")}>
          Resolve
        </Button>
      ) : null}
      {status === "resolved" || status === "suppressed" ? (
        <Button variant="outline" size="sm" disabled={pending} onClick={() => setStatus("open")}>
          Reopen
        </Button>
      ) : null}
      {error ? <span className="text-xs text-destructive">{error}</span> : null}
    </div>
  );
}

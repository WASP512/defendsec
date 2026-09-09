"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";

export function SampleToggle({ hasSamples }: { hasSamples: boolean }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function run(method: "POST" | "DELETE") {
    setPending(true);
    setError("");
    try {
      const response = await fetch("/api/demo", { method });
      if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
      }
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
      setPending(false);
    }
  }

  if (hasSamples) {
    return (
      <div className="flex flex-col items-start gap-1">
        <Button variant="outline" disabled={pending} onClick={() => run("DELETE")}>
          {pending ? "Removing…" : "Remove sample hosts"}
        </Button>
        {error ? <span className="text-xs text-destructive">{error}</span> : null}
      </div>
    );
  }

  return (
    <div className="flex flex-col items-start gap-1">
      <Button variant="outline" disabled={pending} onClick={() => run("POST")}>
        {pending ? "Loading…" : "Load sample fleet"}
      </Button>
      {error ? <span className="text-xs text-destructive">{error}</span> : null}
    </div>
  );
}

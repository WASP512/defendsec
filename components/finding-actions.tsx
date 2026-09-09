"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { FindingStatus } from "@/lib/types";

export function FindingActions({ findingKey, status }: { findingKey: string; status: FindingStatus }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const next = status === "open" ? "acknowledged" : "open";

  async function save() {
    setPending(true);
    await fetch("/api/findings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: findingKey, status: next }),
    });
    setPending(false);
    router.refresh();
  }

  return (
    <Button variant="outline" size="sm" disabled={pending} onClick={save}>
      {status === "open" ? "Acknowledge" : "Reopen"}
    </Button>
  );
}

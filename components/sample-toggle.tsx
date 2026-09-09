"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";

export function SampleToggle({ hasSamples }: { hasSamples: boolean }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function run(method: "POST" | "DELETE") {
    setPending(true);
    await fetch("/api/demo", { method });
    setPending(false);
    router.refresh();
  }

  if (hasSamples) {
    return (
      <Button variant="outline" disabled={pending} onClick={() => run("DELETE")}>
        Remove sample hosts
      </Button>
    );
  }

  return (
    <Button variant="outline" disabled={pending} onClick={() => run("POST")}>
      Load sample fleet
    </Button>
  );
}

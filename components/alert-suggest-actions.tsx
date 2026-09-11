"use client";

import Link from "next/link";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import type { Alert } from "@/lib/alerts";

export function AlertSuggestActions({
  alert,
  readOnly,
}: {
  alert: Alert;
  readOnly?: boolean;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);

  const showIsolateSuggest =
    alert.kind === "fim" && (alert.severity === "critical" || alert.severity === "high");
  const showScaHost =
    alert.kind === "sca" && (alert.severity === "critical" || alert.severity === "high");

  async function suggestIsolate() {
    setPending(true);
    setError("");
    try {
      const response = await fetch(`/api/devices/${alert.deviceId}/command`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "isolate", payload: {} }),
      });
      const data = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(data.error ?? `Request failed (${response.status})`);
      }
      setSent(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    } finally {
      setPending(false);
    }
  }

  if (alert.kind === "vuln") {
    return (
      <div className="flex flex-wrap gap-2">
        <Link
          href={`/advisories?deviceId=${encodeURIComponent(alert.deviceId)}`}
          className="inline-flex h-8 items-center rounded-lg border border-border px-3 text-sm hover:bg-muted"
        >
          View advisories
        </Link>
        <Link
          href={`/devices/${alert.deviceId}`}
          className="inline-flex h-8 items-center rounded-lg border border-border px-3 text-sm hover:bg-muted"
        >
          Open host
        </Link>
      </div>
    );
  }

  if (showScaHost) {
    return (
      <div className="flex flex-wrap gap-2">
        <Link
          href={`/devices/${alert.deviceId}`}
          className="inline-flex h-8 items-center rounded-lg border border-border px-3 text-sm hover:bg-muted"
        >
          Open host response
        </Link>
        <Link
          href={`/alerts?kind=sca&deviceId=${encodeURIComponent(alert.deviceId)}`}
          className="inline-flex h-8 items-center rounded-lg border border-border px-3 text-sm hover:bg-muted"
        >
          SCA alerts
        </Link>
      </div>
    );
  }

  if (!showIsolateSuggest) {
    return null;
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Link
        href={`/devices/${alert.deviceId}`}
        className="inline-flex h-8 items-center rounded-lg border border-border px-3 text-sm hover:bg-muted"
      >
        Open host response
      </Link>
      {readOnly ? (
        <span className="text-xs text-muted-foreground">Viewer: isolate requires admin token</span>
      ) : (
        <AlertDialog>
          <AlertDialogTrigger
            render={<Button variant="destructive" size="sm" disabled={pending || sent} />}
          >
            {sent ? "Isolate queued" : pending ? "Sending…" : "Suggest isolate"}
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Isolate this host?</AlertDialogTitle>
              <AlertDialogDescription>
                This issues a signed isolate command. The agent must be connected over mTLS, and
                network access remains restricted until an administrator releases it.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={() => void suggestIsolate()}>
                Issue isolate command
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {error ? <span className="text-xs text-destructive">{error}</span> : null}
    </div>
  );
}

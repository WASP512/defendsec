"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, Download, ExternalLink, LoaderCircle, Server, TriangleAlert } from "lucide-react";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogMedia, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import type { ServerUpdateState } from "@/lib/server-updates";

export function ServerUpdateCard({
  initial,
  readOnly,
}: {
  initial: ServerUpdateState;
  readOnly: boolean;
}) {
  const [state, setState] = useState(initial);
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState("");
  const active = requesting || state.status.state === "downloading" || state.status.state === "installing";

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => {
      void fetch("/api/server-updates", { cache: "no-store" })
        .then((response) => response.json())
        .then((next: ServerUpdateState) => {
          setState(next);
          if (next.status.state === "completed" || next.status.state === "failed") {
            setRequesting(false);
          }
        })
        .catch(() => {
          // The console is expected to be briefly unavailable while it restarts.
        });
    }, 3_000);
    return () => window.clearInterval(timer);
  }, [active]);

  async function applyUpdate() {
    if (!state.latestVersion) return;
    setRequesting(true);
    setError("");
    try {
      const response = await fetch("/api/server-updates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: state.latestVersion }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error || `Update request failed (${response.status})`);
      setState((current) => ({
        ...current,
        status: {
          state: "downloading",
          message: "The verified release is downloading. This console will restart briefly.",
          version: current.latestVersion,
        },
      }));
    } catch (caught) {
      setRequesting(false);
      setError(caught instanceof Error ? caught.message : "Could not start the update");
    }
  }

  const current = state.currentVersion;
  const latest = state.latestVersion;
  const complete = state.status.state === "completed";
  const failed = state.status.state === "failed";

  return (
    <Card>
      <CardHeader className="gap-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2"><Server className="size-5" /> DefendSec server</CardTitle>
            <CardDescription className="mt-1">
              Verified console and control-plane releases from {state.repo}.
            </CardDescription>
          </div>
          <Badge variant={state.updateAvailable ? "default" : "secondary"}>
            {state.updateAvailable ? "Update available" : latest ? "Up to date" : "Check unavailable"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border bg-muted/20 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Installed</p>
            <p className="mt-1 font-mono text-lg">{current}</p>
          </div>
          <div className="rounded-lg border bg-muted/20 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Latest stable</p>
            <p className="mt-1 font-mono text-lg">{latest ?? "Unavailable"}</p>
          </div>
        </div>

        {state.releaseName && state.updateAvailable ? (
          <div className="space-y-2">
            <p className="font-medium">{state.releaseName}</p>
            {state.notes ? <p className="line-clamp-4 whitespace-pre-line text-sm text-muted-foreground">{state.notes}</p> : null}
            {state.releaseURL ? (
              <a className="inline-flex items-center gap-1 text-sm text-primary hover:underline" href={state.releaseURL} target="_blank" rel="noreferrer">
                Review release notes <ExternalLink className="size-3.5" />
              </a>
            ) : null}
          </div>
        ) : null}

        {active ? (
          <div className="flex items-start gap-3 rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-sm">
            <LoaderCircle className="mt-0.5 size-4 shrink-0 animate-spin text-blue-600" />
            <div><p className="font-medium">Update in progress</p><p className="text-muted-foreground">{state.status.message}</p></div>
          </div>
        ) : complete ? (
          <div className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-600" />
            <div><p className="font-medium">Update completed</p><p className="text-muted-foreground">{state.status.message}</p></div>
          </div>
        ) : failed ? (
          <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm">
            <TriangleAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
            <div><p className="font-medium">Update failed</p><p className="text-muted-foreground">{state.status.message}</p></div>
          </div>
        ) : state.unavailableReason ? (
          <p className="text-sm text-muted-foreground">{state.unavailableReason}</p>
        ) : null}
        {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
      </CardContent>
      <CardFooter className="justify-end">
        <AlertDialog>
          <AlertDialogTrigger
            render={
              <Button disabled={!state.canApply || readOnly || active}>
                {active ? <LoaderCircle className="animate-spin" /> : <Download />}
                {readOnly ? "Admin required" : active ? "Updating…" : "Install update"}
              </Button>
            }
          />
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogMedia><Download /></AlertDialogMedia>
              <AlertDialogTitle>Install DefendSec {latest}?</AlertDialogTitle>
              <AlertDialogDescription>
                The release will be downloaded and verified, then the API and console will restart.
                If health checks fail, the previous binaries are restored automatically.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={() => void applyUpdate()}>Install and restart</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </CardFooter>
    </Card>
  );
}


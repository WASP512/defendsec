"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { CheckCircle2, ExternalLink, Laptop, LoaderCircle, Upload } from "lucide-react";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogMedia, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AgentReleaseArtifact } from "@/lib/server-updates";

export type AgentUpdateTarget = {
  id: string;
  hostname: string;
  arch: "amd64" | "arm64" | "unsupported";
  currentVersion: string;
  online: boolean;
  outdated: boolean;
};

export function AgentUpdatePanel({
  targets,
  artifacts,
  readOnly,
}: {
  targets: AgentUpdateTarget[];
  artifacts: AgentReleaseArtifact[];
  readOnly: boolean;
}) {
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<Record<string, "queued" | "failed">>({});
  const [error, setError] = useState("");
  const artifactByArch = useMemo(() => new Map(artifacts.map((item) => [item.arch, item])), [artifacts]);
  const eligible = targets.filter(
    (target) => target.outdated && target.online && target.arch !== "unsupported" && artifactByArch.has(target.arch),
  );

  async function updateOutdated() {
    setRunning(true);
    setError("");
    const next: Record<string, "queued" | "failed"> = {};
    for (const target of eligible) {
      const artifact = artifactByArch.get(target.arch as "amd64" | "arm64");
      if (!artifact) continue;
      try {
        const response = await fetch(`/api/devices/${target.id}/command`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type: "agent_update",
            payload: {
              version: artifact.version,
              url: artifact.url,
              sha256: artifact.sha256,
            },
          }),
        });
        next[target.id] = response.ok ? "queued" : "failed";
      } catch {
        next[target.id] = "failed";
      }
      setResults({ ...next });
    }
    const failures = Object.values(next).filter((value) => value === "failed").length;
    if (failures) setError(`${failures} agent update request${failures === 1 ? "" : "s"} could not be queued.`);
    setRunning(false);
  }

  return (
    <Card>
      <CardHeader className="gap-3">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div>
            <CardTitle className="flex items-center gap-2"><Laptop className="size-5" /> Enrolled agents</CardTitle>
            <CardDescription className="mt-1">
              Roll out the matching signed binary to connected Linux agents. Each host verifies its sha256 before replacement.
            </CardDescription>
          </div>
          <AlertDialog>
            <AlertDialogTrigger
              render={
                <Button disabled={readOnly || running || eligible.length === 0}>
                  {running ? <LoaderCircle className="animate-spin" /> : <Upload />}
                  {readOnly ? "Admin required" : `Update ${eligible.length} outdated`}
                </Button>
              }
            />
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogMedia><Upload /></AlertDialogMedia>
                <AlertDialogTitle>Update {eligible.length} connected agent{eligible.length === 1 ? "" : "s"}?</AlertDialogTitle>
                <AlertDialogDescription>
                  Signed update commands are queued one host at a time. Agents download the architecture-matched
                  binary, verify its sha256, replace it atomically, and restart under their service manager.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => void updateOutdated()}>Queue agent updates</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Architecture</TableHead>
                <TableHead>Installed agent</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.length ? targets.map((target) => {
                const result = results[target.id];
                const supported = target.arch !== "unsupported" && artifactByArch.has(target.arch);
                return (
                  <TableRow key={target.id}>
                    <TableCell className="font-medium">{target.hostname}</TableCell>
                    <TableCell className="font-mono text-xs">{target.arch}</TableCell>
                    <TableCell className="font-mono text-xs">{target.currentVersion || "Not reported"}</TableCell>
                    <TableCell>
                      {result === "queued" ? (
                        <Badge variant="secondary"><CheckCircle2 /> Queued</Badge>
                      ) : result === "failed" ? (
                        <Badge variant="destructive">Failed</Badge>
                      ) : !target.currentVersion ? (
                        <Badge variant="outline">Unknown</Badge>
                      ) : target.outdated ? (
                        <Badge variant="default">{target.online && supported ? "Update ready" : target.online ? "Unsupported" : "Offline"}</Badge>
                      ) : (
                        <Badge variant="secondary">Current</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" render={<Link href={`/devices/${target.id}`} />}>
                        Open host <ExternalLink />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              }) : (
                <TableRow>
                  <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                    No mTLS agents have reported a version yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
        {artifacts.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Architecture-matched agent artifacts are unavailable in the latest release, so fleet rollout is disabled.
          </p>
        ) : null}
        {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
      </CardContent>
    </Card>
  );
}


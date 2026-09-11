import { AgentUpdatePanel, type AgentUpdateTarget } from "@/components/agent-update-panel";
import { PageHeader } from "@/components/console-ui";
import { ServerUpdateCard } from "@/components/server-update-card";
import { isReadOnlySession } from "@/lib/auth";
import { loadFleet } from "@/lib/mtls-agents";
import { isOnline } from "@/lib/policies";
import { compareVersions, getServerUpdateState, normalizeVersion } from "@/lib/server-updates";
import { ensureStore } from "@/lib/store";

export const dynamic = "force-dynamic";

function agentArch(value: string): AgentUpdateTarget["arch"] {
  const normalized = value.toLowerCase();
  if (normalized === "amd64" || normalized === "x86_64") return "amd64";
  if (normalized === "arm64" || normalized === "aarch64") return "arm64";
  return "unsupported";
}

export default async function UpdatesPage() {
  const [server, store, readOnly] = await Promise.all([
    getServerUpdateState(),
    ensureStore(),
    isReadOnlySession(),
  ]);
  const fleet = await loadFleet(store.devices);
  const latestAgentVersion = server.latestVersion ?? "";
  const targets: AgentUpdateTarget[] = fleet
    .filter((device) => Boolean(device.mtlsDeviceId))
    .map((device) => {
      const comparison = latestAgentVersion
        ? compareVersions(device.agentVersion ?? "", latestAgentVersion)
        : 0;
      return {
        id: device.mtlsDeviceId || device.id,
        hostname: device.hostname,
        arch: agentArch(device.arch),
        currentVersion: device.agentVersion ?? "",
        online: isOnline(device),
        outdated: latestAgentVersion
          ? comparison === null
            ? normalizeVersion(device.agentVersion ?? "") !== normalizeVersion(latestAgentVersion)
            : comparison < 0
          : false,
      };
    })
    .sort((left, right) => Number(right.outdated) - Number(left.outdated) || left.hostname.localeCompare(right.hostname));

  return (
    <div className="mx-auto max-w-6xl space-y-8">
      <PageHeader
        title="Updates"
        description="Keep this self-hosted control plane and its enrolled agents current from one place. Every binary is hash-verified, and server health checks trigger rollback on failure."
      />
      <ServerUpdateCard initial={server} readOnly={readOnly} />
      <AgentUpdatePanel targets={targets} artifacts={server.agentArtifacts} readOnly={readOnly} />
    </div>
  );
}


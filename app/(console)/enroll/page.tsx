import { headers } from "next/headers";
import { EnrollPanel } from "@/components/enroll-panel";
import { ensureStore } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function EnrollPage() {
  const store = await ensureStore();
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "127.0.0.1:47261";
  const proto = headerList.get("x-forwarded-proto") ?? "http";
  const serverUrl = `${proto}://${host}`;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Enroll a host</h1>
        <p className="mt-1 text-muted-foreground">
          Copy the agent from this repo onto a machine that can reach this server. No MDM profile,
          no vendor account — just an HTTP check-in.
        </p>
      </div>
      <EnrollPanel enrollSecret={store.enrollSecret} serverUrl={serverUrl} />
      <div className="space-y-2 text-sm text-muted-foreground">
        <p className="font-medium text-foreground">Go agent (mTLS + signed commands)</p>
        <p>
          Start <code className="text-foreground">keel-apid</code>, then enroll with the same secret.
          First HTTPS call trust-on-first-use pins the CA; after that all gRPC is mTLS.
        </p>
        <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs text-foreground">
{`make apid agent
./bin/keel-apid --data-dir data
./bin/keel-agentd \\
  --server-http https://127.0.0.1:47262 \\
  --server-grpc 127.0.0.1:47263 \\
  --tls-server-name localhost \\
  --enroll-secret YOUR_ENROLL_SECRET \\
  --state-dir data/agent-mtls`}
        </pre>
        <p>
          Unit files: <code className="text-foreground">packaging/systemd</code>,{" "}
          <code className="text-foreground">packaging/launchd</code>.
        </p>
      </div>
      <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
        <li>Copy <code className="text-foreground">agent/keel-agent.py</code> to the host.</li>
        <li>Run the command above. The agent writes a node key next to the script.</li>
        <li>Leave it running (or install as a service yourself). The host appears on Fleet.</li>
      </ol>
    </div>
  );
}

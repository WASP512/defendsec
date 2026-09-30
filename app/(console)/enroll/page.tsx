import { redirect } from "next/navigation";
import { EnrollPanel } from "@/components/enroll-panel";
import { isReadOnlySession } from "@/lib/auth";
import { ensureStore } from "@/lib/store";
import { PageHeader } from "@/components/console-ui";
import { consoleURL } from "@/lib/console-url";

export const dynamic = "force-dynamic";

export default async function EnrollPage() {
  if (await isReadOnlySession()) {
    redirect("/");
  }
  const store = await ensureStore();
  const serverUrl = await consoleURL();

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <PageHeader
        title="Enroll a host"
        description={
          <>
          Run the install command for its platform on each host you want to inventory. Do not re-run the
          Proxmox server helper on those machines.
          </>
        }
      />
      <EnrollPanel enrollSecret={store.enrollSecret} serverUrl={serverUrl} />
      <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
        <li>
          Copy the command for the host&apos;s platform and run it there as root or administrator.
          It downloads the agent from this server, verifies it, and installs it as a service.
        </li>
        <li>
          <code className="text-foreground">--tls-server-name</code> must match the server hostname
          or IP on the certificate (default Proxmox hostname is <code className="text-foreground">defendsec</code>).
        </li>
        <li>
          Confirm the host on <strong>Hosts</strong>, then open it and try a live query from Signed
          response.
        </li>
        <li>
          Server install, ports, and uninstall: <code className="text-foreground">docs/INSTALL.md</code>.
        </li>
      </ol>
    </div>
  );
}

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { EnrollPanel } from "@/components/enroll-panel";
import { isReadOnlySession } from "@/lib/auth";
import { ensureStore } from "@/lib/store";

export const dynamic = "force-dynamic";

export default async function EnrollPage() {
  if (await isReadOnlySession()) {
    redirect("/");
  }
  const store = await ensureStore();
  const headerList = await headers();
  const host = headerList.get("x-forwarded-host") ?? headerList.get("host") ?? "127.0.0.1:47261";
  const proto = headerList.get("x-forwarded-proto") ?? "http";
  const serverUrl =
    process.env.DEFENDSEC_PUBLIC_CONSOLE_URL?.trim().replace(/\/+$/, "") ||
    `${proto}://${host}`;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Enroll a host</h1>
        <p className="mt-1 text-muted-foreground">
          Run the Agent install command on each host you want to inventory. Do not re-run the
          Proxmox server helper on those machines.
        </p>
      </div>
      <EnrollPanel enrollSecret={store.enrollSecret} serverUrl={serverUrl} />
      <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
        <li>
          Copy <strong>Agent install</strong> and run it with sudo on the host. The command downloads
          the agent from this server and enables systemd.
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

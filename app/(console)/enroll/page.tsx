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
          Prefer the Go agent for mTLS inventory and signed response. Fedora workstation steps are in{" "}
          <code className="text-foreground">docs/FEDORA.md</code>.
        </p>
      </div>
      <EnrollPanel enrollSecret={store.enrollSecret} serverUrl={serverUrl} />
      <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
        <li>
          Prefer the <strong>Agent install</strong> one-liner above (downloads binary + systemd). Full
          Proxmox/server setup is in <code className="text-foreground">docs/INSTALL.md</code>.
        </li>
        <li>
          Start <code className="text-foreground">defendsec-apid</code> with a TLS hostname/SAN the
          agent can verify (<code className="text-foreground">--tls-server-name</code> must match).
        </li>
        <li>
          Confirm the host on <strong>Devices</strong>, then try a live query from Signed response.
        </li>
        <li>
          Optional units: <code className="text-foreground">packaging/systemd</code>. Fedora lab notes
          in <code className="text-foreground">docs/FEDORA.md</code>.
        </li>
      </ol>
    </div>
  );
}

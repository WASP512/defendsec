import { LoginForm } from "@/components/login-form";
import { isAuthenticatedSession, isDevFallbackToken } from "@/lib/auth";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  if (await isAuthenticatedSession()) {
    redirect("/");
  }
  const params = await searchParams;
  return (
    <div className="flex min-h-full items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6 rounded-xl border p-8">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">DefendSec</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            There is no username. Paste the admin token from{" "}
            <code className="text-foreground">/var/lib/defendsec/admin-token.txt</code> (on Proxmox:{" "}
            <code className="text-foreground">pct exec &lt;CTID&gt; -- cat /var/lib/defendsec/admin-token.txt</code>
            ). Use <span className="text-foreground">http://</span> on port 47261, not https.
          </p>
        </div>
        <LoginForm showDevHint={await isDevFallbackToken()} failed={params.error === "1"} />
      </div>
    </div>
  );
}

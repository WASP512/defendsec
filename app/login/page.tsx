import { LoginForm } from "@/components/login-form";
import { isAuthenticatedSession, isDevFallbackToken } from "@/lib/auth";
import { apidAccountsExist } from "@/lib/identity";
import { Anchor, LockKeyhole, ShieldCheck } from "lucide-react";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; totp?: string }>;
}) {
  if (await isAuthenticatedSession()) {
    redirect("/");
  }
  const params = await searchParams;
  // With no accounts yet the form offers first-run setup instead of sign-in.
  let accountsExist = true;
  try {
    accountsExist = await apidAccountsExist();
  } catch {
    // Control plane unreachable; assume a configured install rather than
    // exposing setup.
  }
  return (
    <main className="grid min-h-full bg-muted/30 lg:grid-cols-[1.1fr_0.9fr]">
      <section className="hidden border-r bg-primary p-12 text-primary-foreground lg:flex lg:flex-col lg:justify-between">
        <div className="flex items-center gap-2 text-lg font-semibold">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary-foreground/10">
            <Anchor className="size-5" />
          </span>
          DefendSec
        </div>
        <div className="max-w-lg space-y-6">
          <ShieldCheck className="size-10" />
          <div>
            <h1 className="text-4xl font-semibold tracking-tight">Your fleet, under your control.</h1>
            <p className="mt-4 text-lg text-primary-foreground/70">
              Self-hosted host inventory, vulnerability findings, policy checks, and file integrity.
            </p>
          </div>
        </div>
        <p className="text-sm text-primary-foreground/60">No vendor account. No subscription.</p>
      </section>
      <section className="flex items-center justify-center px-4 py-12 sm:px-8">
        <div className="w-full max-w-md">
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-2 text-lg font-semibold">
              <Anchor className="size-5" />
              DefendSec
            </div>
          </div>
          <div className="rounded-2xl border bg-background p-6 shadow-sm sm:p-8">
            <div className="mb-6">
              <span className="mb-4 flex size-10 items-center justify-center rounded-lg bg-muted">
                <LockKeyhole className="size-5" />
              </span>
              <h2 className="text-2xl font-semibold tracking-tight">Sign in to the console</h2>
              <p className="mt-2 text-sm text-muted-foreground">
                {accountsExist
                  ? "Sign in with your account. Every action is recorded against your name."
                  : "First run. Sign in with the admin token to create an administrator."}
              </p>
            </div>
            <LoginForm
              showDevHint={await isDevFallbackToken()}
              failed={params.error === "1"}
              locked={params.error === "locked"}
              unavailable={params.error === "unavailable"}
              totpRequired={params.totp === "1"}
              accountsExist={accountsExist}
            />
          </div>
          <p className="mt-4 text-center text-xs text-muted-foreground">
            Console traffic uses HTTP on port 47261. Agent enrollment uses TLS.
          </p>
        </div>
      </section>
    </main>
  );
}

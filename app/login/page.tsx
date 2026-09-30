import { LoginForm } from "@/components/login-form";
import { isAuthenticatedSession, isDevFallbackToken } from "@/lib/auth";
import { apidSetupStatus, apidSSOStatus } from "@/lib/identity";
import { cleanInvite, loginState } from "@/lib/login-state";
import { Anchor, LockKeyhole, ShieldCheck } from "lucide-react";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{
    error?: string;
    totp?: string;
    setupError?: string;
    created?: string;
    ssoError?: string;
    invite?: string;
  }>;
}) {
  if (await isAuthenticatedSession()) {
    redirect("/");
  }
  const params = await searchParams;
  // Decided from the control plane's own unauthenticated setup status, rather
  // than from a signed-in endpoint whose 401 used to be read as "accounts
  // exist" — which hid first-run setup on every fresh install.
  const invite = cleanInvite(params.invite);
  const [setup, sso] = await Promise.all([apidSetupStatus(invite), apidSSOStatus()]);
  const state = loginState(setup);
  // Both setup states are the same task — claiming an unclaimed install —
  // so they share one heading, as Paperclip's does.
  const isSetup = state.kind === "setup" || state.kind === "setup-closed";
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
              <h2 className="text-2xl font-semibold tracking-tight">
                {isSetup ? "Finish setting up DefendSec" : "Sign in to the console"}
              </h2>
              <p className="mt-2 text-sm text-muted-foreground">
                {isSetup
                  ? "No administrator has claimed this instance yet. Create your account to become the first administrator."
                  : "Sign in with your account. Every action is recorded against your name."}
              </p>
            </div>
            <LoginForm
              state={state}
              showDevHint={await isDevFallbackToken()}
              failed={params.error === "1"}
              locked={params.error === "locked"}
              unavailable={params.error === "unavailable"}
              totpRequired={params.totp === "1"}
              setupError={params.setupError}
              invite={invite}
              created={params.created === "1"}
              sso={sso}
              ssoError={params.ssoError}
            />
          </div>
          <p className="mt-4 text-center text-xs text-muted-foreground">
            Self-hosted. Nothing here is sent to a vendor.
          </p>
        </div>
      </section>
    </main>
  );
}

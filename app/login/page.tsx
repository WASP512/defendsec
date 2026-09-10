import { LoginForm } from "@/components/login-form";
import { isAdminSession, isDevFallbackToken } from "@/lib/auth";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  if (await isAdminSession()) {
    redirect("/");
  }
  return (
    <div className="flex min-h-full items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6 rounded-xl border p-8">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Keel</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Sign in with the admin token. Agent check-in still uses the enroll secret and node key
            only.
          </p>
        </div>
        <LoginForm showDevHint={await isDevFallbackToken()} />
      </div>
    </div>
  );
}

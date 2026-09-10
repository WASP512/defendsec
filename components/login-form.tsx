"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DEV_ADMIN_TOKEN } from "@/lib/auth-public";

export function LoginForm({ showDevHint }: { showDevHint: boolean }) {
  const router = useRouter();
  const [token, setToken] = useState(showDevHint ? DEV_ADMIN_TOKEN : "");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError("");
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ token }),
    });
    setPending(false);
    if (!response.ok) {
      setError("That token was rejected.");
      return;
    }
    router.replace("/");
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="token">Admin token</Label>
        <Input
          id="token"
          type="password"
          autoComplete="current-password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          required
        />
      </div>
      {showDevHint ? (
        <p className="text-sm text-muted-foreground">
          Development fallback is <code className="text-foreground">{DEV_ADMIN_TOKEN}</code>. Set{" "}
          <code className="text-foreground">KEEL_ADMIN_TOKEN</code> or use{" "}
          <code className="text-foreground">data/admin-token.txt</code> in production.
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">
          Use <code className="text-foreground">KEEL_ADMIN_TOKEN</code> or the value in{" "}
          <code className="text-foreground">data/admin-token.txt</code> on the server.
        </p>
      )}
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <Button type="submit" disabled={pending} className="w-full">
        {pending ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}

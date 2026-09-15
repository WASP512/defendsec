import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DEV_ADMIN_TOKEN } from "@/lib/auth-public";

export function LoginForm({
  showDevHint,
  failed,
  locked,
  unavailable,
  totpRequired,
  accountsExist,
}: {
  showDevHint: boolean;
  failed: boolean;
  locked?: boolean;
  unavailable?: boolean;
  totpRequired?: boolean;
  accountsExist?: boolean;
}) {
  // With no accounts yet, a shared token is the only way in — and the way the
  // first named administrator gets created.
  if (accountsExist === false) {
    return (
      <form action="/api/login" method="post" className="space-y-4">
        <div className="rounded-lg border border-dashed bg-muted/40 p-3 text-sm text-muted-foreground">
          No accounts exist yet. Sign in with the admin token, then create the first
          administrator so your actions are recorded against a person rather than a shared token.
        </div>
        <div className="space-y-2">
          <Label htmlFor="token">Admin token</Label>
          <Input
            id="token"
            name="token"
            type="password"
            autoComplete="current-password"
            required
            placeholder="Paste admin token"
            defaultValue={showDevHint ? DEV_ADMIN_TOKEN : ""}
          />
        </div>
        {showDevHint ? (
          <p className="text-sm text-muted-foreground">
            Development fallback is <code className="text-foreground">{DEV_ADMIN_TOKEN}</code>.
          </p>
        ) : (
          <p className="text-sm text-muted-foreground">
            Packaged installs store it at{" "}
            <code className="text-foreground">/var/lib/defendsec/admin-token.txt</code>.
          </p>
        )}
        {failed ? <p className="text-sm text-destructive">That token was rejected.</p> : null}
        <Button type="submit" className="h-10 w-full">
          Continue to setup
        </Button>
      </form>
    );
  }

  return (
    <form action="/api/login" method="post" className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="username">Username</Label>
        <Input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
          placeholder="alice"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="totpCode">
          Authenticator code{" "}
          <span className="font-normal text-muted-foreground">
            {totpRequired ? "" : "(if enabled)"}
          </span>
        </Label>
        <Input
          id="totpCode"
          name="totpCode"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]*"
          maxLength={6}
          placeholder="123456"
          autoFocus={totpRequired}
        />
      </div>

      {totpRequired ? (
        <p className="text-sm text-muted-foreground">
          Enter the six-digit code from your authenticator app.
        </p>
      ) : null}
      {failed ? <p className="text-sm text-destructive">Those credentials were rejected.</p> : null}
      {locked ? (
        <p className="text-sm text-destructive">
          Too many failed attempts. This account is locked for 15 minutes.
        </p>
      ) : null}
      {unavailable ? (
        <p className="text-sm text-destructive">
          The control plane is not reachable. Start <code>defendsec-apid</code> and try again.
        </p>
      ) : null}

      <Button type="submit" className="h-10 w-full">
        Sign in
      </Button>

      <details className="text-xs text-muted-foreground">
        <summary className="cursor-pointer">Sign in with a shared token instead</summary>
        <div className="mt-3 space-y-2">
          <Label htmlFor="token" className="text-xs">
            Admin or viewer token
          </Label>
          <Input id="token" name="token" type="password" placeholder="Paste access token" />
          <p className="leading-relaxed">
            Shared tokens still work for scripts and recovery, but actions taken under one are
            recorded as unattributed — they cannot be traced to a person.
          </p>
        </div>
      </details>
    </form>
  );
}

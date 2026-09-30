import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DEV_ADMIN_TOKEN } from "@/lib/auth-public";
import type { LoginState } from "@/lib/login-state";

// Sign-in, first-run setup, and the shared-token fallback.
//
// Each is its own <form>. The token field used to sit inside the account form,
// whose username and password were marked required, so a browser refused to
// submit the token until those were filled — and filling them sent the request
// down the account path instead. Separate forms cannot interfere.

function SetupForm({ minutesRemaining, error }: { minutesRemaining: number; error?: string }) {
  return (
    <form action="/api/setup" method="post" className="space-y-4">
      <div className="rounded-lg border border-dashed bg-muted/40 p-3 text-sm text-muted-foreground">
        This is a new install. Create the first administrator account. Setup stays open for about{" "}
        {minutesRemaining} more {minutesRemaining === 1 ? "minute" : "minutes"}, and closes as soon
        as this account exists.
      </div>
      <div className="space-y-2">
        <Label htmlFor="setup-username">Username</Label>
        <Input
          id="setup-username"
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
          autoFocus
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="setup-display">
          Display name <span className="font-normal text-muted-foreground">(optional)</span>
        </Label>
        <Input id="setup-display" name="displayName" autoComplete="name" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="setup-password">Password</Label>
        <Input
          id="setup-password"
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={12}
          required
        />
        <p className="text-xs text-muted-foreground">At least 12 characters.</p>
      </div>
      <div className="space-y-2">
        <Label htmlFor="setup-confirm">Confirm password</Label>
        <Input
          id="setup-confirm"
          name="confirm"
          type="password"
          autoComplete="new-password"
          minLength={12}
          required
        />
      </div>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <Button type="submit" className="h-10 w-full">
        Create administrator and sign in
      </Button>
    </form>
  );
}

function SignInForm({
  failed,
  locked,
  unavailable,
  totpRequired,
  created,
}: {
  failed: boolean;
  locked?: boolean;
  unavailable?: boolean;
  totpRequired?: boolean;
  created?: boolean;
}) {
  return (
    <form action="/api/login" method="post" className="space-y-4">
      {created ? (
        <p className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm">
          Your account was created. Sign in with it.
        </p>
      ) : null}
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
            {totpRequired ? "" : "(only if you enabled it)"}
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
    </form>
  );
}

function TokenForm({
  open,
  failed,
  showDevHint,
}: {
  open?: boolean;
  failed?: boolean;
  showDevHint: boolean;
}) {
  return (
    <details className="text-xs text-muted-foreground" open={open}>
      <summary className="cursor-pointer">Sign in with the admin token instead</summary>
      {/* A separate form, so nothing in the account form can block it. */}
      <form action="/api/login" method="post" className="mt-3 space-y-2">
        <Label htmlFor="token" className="text-xs">
          Admin or viewer token
        </Label>
        <Input
          id="token"
          name="token"
          type="password"
          required
          placeholder="Paste the token"
          defaultValue={showDevHint ? DEV_ADMIN_TOKEN : ""}
        />
        <p className="leading-relaxed">
          On a packaged install it is in <code>/var/lib/defendsec/admin-token.txt</code>. Actions
          taken with it are recorded as unattributed, because they cannot be traced to a person.
        </p>
        {failed ? <p className="text-destructive">That token was rejected.</p> : null}
        <Button type="submit" variant="outline" className="h-9 w-full">
          Sign in with token
        </Button>
      </form>
    </details>
  );
}

function SSOButton({ name, error }: { name: string; error?: string }) {
  return (
    <div className="space-y-2">
      {/* A link, not a form: the start route redirects to the identity provider. */}
      <a
        href="/api/sso/start"
        className="flex h-10 w-full items-center justify-center rounded-md border bg-background text-sm font-medium hover:bg-muted"
      >
        Sign in with {name}
      </a>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span className="h-px flex-1 bg-border" />
        or
        <span className="h-px flex-1 bg-border" />
      </div>
    </div>
  );
}

export function LoginForm({
  state,
  showDevHint,
  failed,
  locked,
  unavailable,
  totpRequired,
  setupError,
  created,
  sso,
  ssoError,
}: {
  sso?: { enabled: boolean; displayName?: string };
  ssoError?: string;
  state: LoginState;
  showDevHint: boolean;
  failed: boolean;
  locked?: boolean;
  unavailable?: boolean;
  totpRequired?: boolean;
  setupError?: string;
  created?: boolean;
}) {
  const ssoButton = sso?.enabled ? (
    <SSOButton name={sso.displayName || "single sign-on"} error={ssoError} />
  ) : ssoError ? (
    <p className="text-sm text-destructive">{ssoError}</p>
  ) : null;

  switch (state.kind) {
    case "setup":
      return (
        <div className="space-y-5">
          {ssoButton}
          <SetupForm minutesRemaining={state.minutesRemaining} error={setupError} />
          <TokenForm showDevHint={showDevHint} failed={failed} />
        </div>
      );

    case "setup-closed":
      return (
        <div className="space-y-5">
          {ssoButton}
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <p className="font-medium">First-run setup has closed.</p>
            <p className="mt-1 text-muted-foreground">
              It stays open for 30 minutes after the control plane starts, so that only someone
              with access to the server can reopen it. To create your administrator, restart it
              and reload this page:
            </p>
            <pre className="mt-2 overflow-x-auto rounded bg-background p-2 text-xs">
              systemctl restart defendsec-apid
            </pre>
            <p className="mt-2 text-muted-foreground">Or sign in with the admin token below.</p>
          </div>
          <TokenForm open showDevHint={showDevHint} failed={failed} />
        </div>
      );

    case "token-only":
      return (
        <div className="space-y-5">
          <p className="rounded-lg border border-dashed bg-muted/40 p-3 text-sm text-muted-foreground">
            No database is configured, so named accounts are unavailable. Sign in with the admin
            token.
          </p>
          <TokenForm open showDevHint={showDevHint} failed={failed} />
        </div>
      );

    case "unavailable":
      return (
        <div className="space-y-5">
          <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            The control plane is not reachable, so accounts cannot be checked. Start it with{" "}
            <code>systemctl start defendsec-apid</code> and reload this page.
          </p>
          <TokenForm open showDevHint={showDevHint} failed={failed} />
        </div>
      );

    case "signin":
      return (
        <div className="space-y-5">
          {ssoButton}
          <SignInForm
            failed={failed}
            locked={locked}
            unavailable={unavailable}
            totpRequired={totpRequired}
            created={created}
          />
          <TokenForm showDevHint={showDevHint} />
        </div>
      );
  }
}

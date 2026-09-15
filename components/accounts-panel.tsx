"use client";

import { useState, useTransition } from "react";
import { KeyRound, ShieldAlert, ShieldCheck, UserPlus } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { IdentityUser } from "@/lib/identity";

type Feedback = { kind: "ok" | "error"; message: string } | null;

async function postJSON(url: string, body: unknown, method = "POST") {
  const res = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let parsed: { error?: string } = {};
  try {
    parsed = (await res.json()) as typeof parsed;
  } catch {
    // no body
  }
  if (!res.ok) throw new Error(parsed.error ?? `Request failed (${res.status})`);
  return parsed;
}

export function AccountsPanel({
  users,
  currentUserId,
  currentUsername,
  actorIdentity,
  totpEnabled,
  loadError,
}: {
  users: IdentityUser[];
  currentUserId: string | null;
  currentUsername: string | null;
  actorIdentity: string;
  totpEnabled: boolean;
  loadError: string | null;
}) {
  const unattributed = actorIdentity.startsWith("unattributed:");

  return (
    <div className="space-y-6">
      {unattributed ? (
        <div className="flex gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-600" />
          <div className="space-y-1">
            <p className="font-medium">This session is signed in with a shared token.</p>
            <p className="text-muted-foreground">
              Actions you take now are recorded as{" "}
              <code className="text-foreground">{actorIdentity}</code> and cannot be traced to a
              person. Create an account below, then sign in with it.
            </p>
          </div>
        </div>
      ) : null}

      {loadError ? (
        <p className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
          {loadError}
        </p>
      ) : null}

      <CreateAccount />
      {currentUserId ? (
        <SecondFactor enabled={totpEnabled} username={currentUsername ?? ""} />
      ) : null}
      <AccountList users={users} currentUserId={currentUserId} />
    </div>
  );
}

function CreateAccount() {
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [pending, startTransition] = useTransition();

  return (
    <section className="rounded-xl border bg-background p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <UserPlus className="size-4" /> Create an account
      </h3>
      <form
        className="mt-4 grid gap-3 sm:grid-cols-2"
        onSubmit={(event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const data = new FormData(form);
          setFeedback(null);
          startTransition(async () => {
            try {
              await postJSON("/api/users", {
                username: String(data.get("username") ?? ""),
                displayName: String(data.get("displayName") ?? ""),
                role: String(data.get("role") ?? "admin"),
                password: String(data.get("password") ?? ""),
              });
              setFeedback({ kind: "ok", message: "Account created." });
              form.reset();
              // A new row changes what the server rendered.
              window.location.reload();
            } catch (err) {
              setFeedback({ kind: "error", message: (err as Error).message });
            }
          });
        }}
      >
        <div className="space-y-2">
          <Label htmlFor="new-username">Username</Label>
          <Input
            id="new-username"
            name="username"
            required
            autoCapitalize="none"
            spellCheck={false}
            placeholder="alice"
          />
          <p className="text-xs text-muted-foreground">
            Lowercase letters, digits, and <code>. - _ @</code>
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="new-display">Display name</Label>
          <Input id="new-display" name="displayName" placeholder="Alice Nguyen" />
        </div>
        <div className="space-y-2">
          <Label htmlFor="new-role">Role</Label>
          <select
            id="new-role"
            name="role"
            defaultValue="admin"
            className="h-9 w-full rounded-md border bg-transparent px-3 text-sm"
          >
            <option value="admin">Admin — can respond and change state</option>
            <option value="viewer">Viewer — read only</option>
          </select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="new-password">Password</Label>
          <Input
            id="new-password"
            name="password"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
          />
          <p className="text-xs text-muted-foreground">At least 12 characters.</p>
        </div>
        <div className="sm:col-span-2">
          <Button type="submit" disabled={pending}>
            {pending ? "Creating…" : "Create account"}
          </Button>
          {feedback ? (
            <span
              className={`ml-3 text-sm ${
                feedback.kind === "ok" ? "text-muted-foreground" : "text-destructive"
              }`}
            >
              {feedback.message}
            </span>
          ) : null}
        </div>
      </form>
    </section>
  );
}

function SecondFactor({ enabled, username }: { enabled: boolean; username: string }) {
  const [secret, setSecret] = useState("");
  const [uri, setUri] = useState("");
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [pending, startTransition] = useTransition();

  if (enabled) {
    return (
      <section className="rounded-xl border bg-background p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <ShieldCheck className="size-4 text-emerald-600" /> Two-factor authentication is on
        </h3>
        <p className="mt-2 text-sm text-muted-foreground">
          Your account requires an authenticator code at sign-in. Each code can only be used once.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-xl border bg-background p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <KeyRound className="size-4" /> Set up two-factor authentication
      </h3>
      <p className="mt-2 text-sm text-muted-foreground">
        Nothing is saved until you confirm a code, so a mis-scanned setup cannot lock you out.
      </p>

      {!secret ? (
        <Button
          className="mt-4"
          variant="outline"
          disabled={pending}
          onClick={() =>
            startTransition(async () => {
              setFeedback(null);
              try {
                const body = (await postJSON("/api/totp", { step: "begin" })) as unknown as {
                  secret: string;
                  uri: string;
                };
                setSecret(body.secret);
                setUri(body.uri);
              } catch (err) {
                setFeedback({ kind: "error", message: (err as Error).message });
              }
            })
          }
        >
          {pending ? "Starting…" : "Begin setup"}
        </Button>
      ) : (
        <form
          className="mt-4 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            const code = String(new FormData(event.currentTarget).get("code") ?? "");
            setFeedback(null);
            startTransition(async () => {
              try {
                await postJSON("/api/totp", { step: "confirm", secret, code });
                setFeedback({ kind: "ok", message: "Two-factor authentication enabled." });
                window.location.reload();
              } catch (err) {
                setFeedback({ kind: "error", message: (err as Error).message });
              }
            });
          }}
        >
          <div className="space-y-1">
            <Label>Add this to your authenticator</Label>
            <code className="block overflow-x-auto rounded-md border bg-muted/40 p-3 text-xs">
              {secret}
            </code>
            <p className="text-xs text-muted-foreground">
              Account <code className="text-foreground">{username}</code>, issuer DefendSec,
              SHA-1, 6 digits, 30 seconds. Or paste this URI into your app:
            </p>
            <code className="block overflow-x-auto rounded-md border bg-muted/40 p-2 text-[11px]">
              {uri}
            </code>
          </div>
          <div className="space-y-2">
            <Label htmlFor="totp-confirm">Code from your app</Label>
            <Input
              id="totp-confirm"
              name="code"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              required
              placeholder="123456"
              className="max-w-[10rem]"
            />
          </div>
          <Button type="submit" disabled={pending}>
            {pending ? "Confirming…" : "Confirm and enable"}
          </Button>
          {feedback ? (
            <span
              className={`ml-3 text-sm ${
                feedback.kind === "ok" ? "text-muted-foreground" : "text-destructive"
              }`}
            >
              {feedback.message}
            </span>
          ) : null}
        </form>
      )}
      {!secret && feedback ? (
        <p className="mt-3 text-sm text-destructive">{feedback.message}</p>
      ) : null}
    </section>
  );
}

function AccountList({
  users,
  currentUserId,
}: {
  users: IdentityUser[];
  currentUserId: string | null;
}) {
  return (
    <section className="rounded-xl border bg-background">
      <div className="border-b px-5 py-4">
        <h3 className="text-sm font-semibold">
          Accounts <span className="font-normal text-muted-foreground">({users.length})</span>
        </h3>
      </div>
      {users.length === 0 ? (
        <p className="px-5 py-6 text-sm text-muted-foreground">
          No accounts yet. Create the first one above.
        </p>
      ) : (
        <ul className="divide-y">
          {users.map((user) => (
            <AccountRow key={user.id} user={user} isSelf={user.id === currentUserId} />
          ))}
        </ul>
      )}
    </section>
  );
}

function AccountRow({ user, isSelf }: { user: IdentityUser; isSelf: boolean }) {
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [pending, startTransition] = useTransition();

  const act = (body: Record<string, unknown>, reload: boolean) =>
    startTransition(async () => {
      setFeedback(null);
      try {
        await postJSON("/api/users", { userId: user.id, ...body }, "PATCH");
        if (reload) {
          window.location.reload();
        } else {
          setFeedback({ kind: "ok", message: "Password updated." });
        }
      } catch (err) {
        setFeedback({ kind: "error", message: (err as Error).message });
      }
    });

  return (
    <li className="space-y-3 px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">
            {user.username}
            {isSelf ? <span className="ml-2 text-xs text-muted-foreground">(you)</span> : null}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {user.displayName ? `${user.displayName} · ` : ""}
            {user.role}
            {user.totpEnabled ? " · 2FA on" : " · 2FA off"}
            {user.disabled ? " · disabled" : ""}
          </p>
        </div>
        {!isSelf ? (
          <Button
            variant="outline"
            size="sm"
            disabled={pending}
            onClick={() => act({ disabled: !user.disabled }, true)}
          >
            {user.disabled ? "Enable" : "Disable"}
          </Button>
        ) : null}
      </div>

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const form = event.currentTarget;
          const password = String(new FormData(form).get("password") ?? "");
          act({ password }, false);
          form.reset();
        }}
      >
        <div className="space-y-1">
          <Label htmlFor={`pw-${user.id}`} className="text-xs">
            Set a new password
          </Label>
          <Input
            id={`pw-${user.id}`}
            name="password"
            type="password"
            minLength={12}
            required
            autoComplete="new-password"
            className="h-8 w-56 text-sm"
          />
        </div>
        <Button type="submit" variant="ghost" size="sm" disabled={pending}>
          Update
        </Button>
        {feedback ? (
          <span
            className={`text-xs ${
              feedback.kind === "ok" ? "text-muted-foreground" : "text-destructive"
            }`}
          >
            {feedback.message}
          </span>
        ) : null}
      </form>
    </li>
  );
}

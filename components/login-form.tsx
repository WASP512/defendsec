import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DEV_ADMIN_TOKEN } from "@/lib/auth-public";

export function LoginForm({
  showDevHint,
  failed,
}: {
  showDevHint: boolean;
  failed: boolean;
}) {
  return (
    <form action="/api/login" method="post" className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="token">Admin token</Label>
        <Input
          id="token"
          name="token"
          type="password"
          autoComplete="current-password"
          required
          defaultValue={showDevHint ? DEV_ADMIN_TOKEN : ""}
        />
      </div>
      {showDevHint ? (
        <p className="text-sm text-muted-foreground">
          Development fallback is <code className="text-foreground">{DEV_ADMIN_TOKEN}</code>. Set{" "}
          <code className="text-foreground">DEFENDSEC_ADMIN_TOKEN</code> or use{" "}
          <code className="text-foreground">data/admin-token.txt</code> in production.
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">
          Use <code className="text-foreground">DEFENDSEC_ADMIN_TOKEN</code> or the value in{" "}
          <code className="text-foreground">data/admin-token.txt</code> on the server.
        </p>
      )}
      {failed ? <p className="text-sm text-destructive">That token was rejected.</p> : null}
      <Button type="submit" className="w-full">
        Sign in
      </Button>
    </form>
  );
}

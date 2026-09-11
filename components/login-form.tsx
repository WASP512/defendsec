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
        <Label htmlFor="token">Admin or viewer token</Label>
        <Input
          id="token"
          name="token"
          type="password"
          autoComplete="current-password"
          required
          placeholder="Paste access token"
          defaultValue={showDevHint ? DEV_ADMIN_TOKEN : ""}
        />
      </div>
      {showDevHint ? (
        <p className="text-sm text-muted-foreground">
          Development fallback is <code className="text-foreground">{DEV_ADMIN_TOKEN}</code>. Set{" "}
          <code className="text-foreground">DEFENDSEC_ADMIN_TOKEN</code> or use{" "}
          <code className="text-foreground">data/admin-token.txt</code> in a source checkout.
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">
          Use <code className="text-foreground">DEFENDSEC_ADMIN_TOKEN</code>. Packaged installs also
          store it at <code className="text-foreground">/var/lib/defendsec/admin-token.txt</code>.
        </p>
      )}
      {failed ? <p className="text-sm text-destructive">That token was rejected.</p> : null}
      <Button type="submit" className="h-10 w-full">
        Access console
      </Button>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Packaged installs store the token at{" "}
        <code className="text-foreground">/var/lib/defendsec/admin-token.txt</code>.
      </p>
    </form>
  );
}

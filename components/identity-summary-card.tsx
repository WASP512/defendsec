import Link from "next/link";
import { KeyRound } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { identityCard } from "@/lib/identity-exposure";
import type { IdentitySummary } from "@/lib/exposure-model";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  critical: "border-destructive/50",
  warning: "border-amber-500/50",
  good: "border-emerald-500/40",
  neutral: "",
};

/**
 * What the client's Microsoft 365 tenant says about its accounts: findings by
 * severity and how long ago it was read. A tenant that was never read, or a check
 * that could not run, is said plainly so that zero findings is never read as more
 * than it is. Counts come from the control plane.
 */
export function IdentitySummaryCard({ summary }: { summary: IdentitySummary | undefined }) {
  const card = identityCard(summary);
  return (
    <Card data-identity-summary={card.state} className={cn(TONE[card.tone])}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <KeyRound className="size-4" />
          Accounts and mail rules
        </CardTitle>
        <CardDescription>MFA, administrator roles, legacy sign-in and inbox rules, read from the tenant. No message is read.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className={cn("font-medium", card.tone === "critical" && "text-destructive")} data-identity-headline>
          {card.headline}
        </p>
        {card.lines.map((l) => (
          <p key={l} className="text-muted-foreground">
            {l}
          </p>
        ))}
        <p className="pt-1">
          <Link href="/identity" className="underline">
            Identity
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}

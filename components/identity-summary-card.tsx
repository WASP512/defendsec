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
 * What the client's Microsoft 365 tenant or Google Workspace domain says about its
 * accounts: findings by severity and how long ago it was read. One that was never
 * read, or a check
 * that could not run, is said plainly so that zero findings is never read as more
 * than it is. Counts come from the control plane.
 */
export function IdentitySummaryCard({ summary }: { summary: IdentitySummary | undefined }) {
  const card = identityCard(summary);
  // One provider connected: its own page; both or none: the Microsoft 365 page, whose tabs lead to the other.
  const href = summary?.providers?.length === 1 && summary.providers[0] === "google" ? "/identity/google" : "/identity";
  return (
    <Card data-identity-summary={card.state} className={cn(TONE[card.tone])}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <KeyRound className="size-4" />
          Accounts and mail rules
        </CardTitle>
        <CardDescription>MFA or 2-Step Verification, administrator roles, legacy sign-in, and inbox rules or Gmail filters, read from the tenant or domain. No message is read.</CardDescription>
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
          <Link href={href} className="underline">
            Identity
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}

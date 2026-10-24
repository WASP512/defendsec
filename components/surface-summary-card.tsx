import Link from "next/link";
import { Globe } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { surfaceCard } from "@/lib/surface-exposure";
import type { SurfaceSummary } from "@/lib/exposure-model";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  critical: "border-destructive/50",
  warning: "border-amber-500/50",
  good: "border-emerald-500/40",
  neutral: "",
};

/**
 * What the outside world sees: "External surface: N findings (x high) across M
 * assets, last scanned <time>". Counts come from the control plane. A surface
 * that was never scanned, or whose checks could not run, says so instead of
 * reading as clean.
 */
export function SurfaceSummaryCard({ summary }: { summary: SurfaceSummary | undefined }) {
  const card = surfaceCard(summary);
  return (
    <Card data-surface-summary={card.state} className={cn(TONE[card.tone])}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Globe className="size-4" />
          Seen from outside
        </CardTitle>
        <CardDescription>DNS, email authentication, certificates and open ports on the assets you declared.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className={cn("font-medium", card.tone === "critical" && "text-destructive")} data-surface-headline>
          {card.headline}
        </p>
        {card.lines.map((l) => (
          <p key={l} className="text-muted-foreground">
            {l}
          </p>
        ))}
        <p className="flex gap-3 pt-1">
          <Link href="/surface" className="underline">
            Surface findings
          </Link>
          <Link href="/assets" className="underline">
            Assets
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}

import Link from "next/link";
import { Monitor } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { rmmCard, type RmmStatus } from "@/lib/rmm-model";
import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  critical: "border-destructive/50",
  warning: "border-amber-500/50",
  good: "border-emerald-500/40",
  neutral: "",
};

/**
 * Windows devices read through Datto RMM: how many, what is missing, and, as
 * prominently, what was not assessed. Counts come from the control plane.
 */
export function RmmSummaryCard({ status }: { status: RmmStatus | null }) {
  const card = rmmCard(status);
  return (
    <Card data-rmm-summary={card.state} className={cn(TONE[card.tone])}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Monitor className="size-4" />
          Windows via Datto RMM
        </CardTitle>
        <CardDescription>OS, software and missing updates read from the RMM. Nothing is installed on the PCs.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className={cn("font-medium", card.tone === "critical" && "text-destructive")} data-rmm-headline>
          {card.headline}
        </p>
        {card.lines.map((l) => (
          <p key={l} className="text-muted-foreground">
            {l}
          </p>
        ))}
        <p className="pt-1">
          <Link href="/rmm" className="underline">
            Datto RMM
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}

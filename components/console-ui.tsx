import type { LucideIcon } from "lucide-react";
import { CircleDot, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function PageHeader({
  title,
  description,
  eyebrow,
  actions,
}: {
  title: string;
  description: React.ReactNode;
  eyebrow?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? <div className="mb-2 text-sm text-muted-foreground">{eyebrow}</div> : null}
        <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
        <div className="mt-1 max-w-3xl text-muted-foreground">{description}</div>
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  tone = "neutral",
}: {
  title: string;
  value: React.ReactNode;
  subtitle: React.ReactNode;
  icon: LucideIcon;
  tone?: "neutral" | "good" | "warning" | "critical";
}) {
  const tones = {
    neutral: "bg-primary/10 text-primary",
    good: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
    warning: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
    critical: "bg-destructive/10 text-destructive",
  };

  return (
    <Card className="w-full">
      <CardHeader className="grid grid-cols-[1fr_auto] items-center gap-3">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div className={cn("rounded-lg p-2", tones[tone])}>
          <Icon className="size-4" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
        <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
      </CardContent>
    </Card>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon: Icon = ShieldCheck,
  compact = false,
}: {
  title: string;
  description: React.ReactNode;
  action?: React.ReactNode;
  icon?: LucideIcon;
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-dashed bg-muted/20 px-6 text-center",
        compact ? "py-8" : "py-12",
      )}
    >
      <div className="mb-4 rounded-full border bg-background p-3 shadow-sm">
        <Icon className="size-5 text-muted-foreground" />
      </div>
      <h2 className="font-medium">{title}</h2>
      <div className="mt-1 max-w-md text-sm text-muted-foreground">{description}</div>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ActivityList({ children }: { children: React.ReactNode }) {
  return <ul className="space-y-2">{children}</ul>;
}

export function ActivityItem({
  title,
  description,
  meta,
  actions,
  tone = "neutral",
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  tone?: "neutral" | "good" | "warning" | "critical";
}) {
  const tones = {
    neutral: "bg-muted-foreground",
    good: "bg-emerald-500",
    warning: "bg-amber-500",
    critical: "bg-destructive",
  };

  return (
    <li className="flex flex-col gap-3 rounded-xl border bg-card p-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 gap-3">
        <div className="relative mt-1 shrink-0">
          <CircleDot className="size-5 text-muted-foreground" />
          <span className={cn("absolute left-1/2 top-1/2 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full", tones[tone])} />
        </div>
        <div className="min-w-0 space-y-1">
          <div className="font-medium">{title}</div>
          {description ? <div className="text-sm text-muted-foreground">{description}</div> : null}
          {meta ? <div className="text-xs text-muted-foreground">{meta}</div> : null}
        </div>
      </div>
      {actions ? <div className="shrink-0">{actions}</div> : null}
    </li>
  );
}

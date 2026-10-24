import { AlertTriangle, CheckCircle2, CircleHelp } from "lucide-react";
import { cn } from "@/lib/utils";
import { feedBanner, type FeedsResponse } from "@/lib/feed-banner";

/**
 * How old the vulnerability data is, on the Advisories page. Red if any feed
 * is more than seven days old (or has never synced), amber if the age cannot
 * be established, plain if everything is current.
 */
export function FeedAgeBanner({ status }: { status: FeedsResponse | null }) {
  const banner = feedBanner(status);
  const Icon = banner.tone === "red" ? AlertTriangle : banner.tone === "amber" ? CircleHelp : CheckCircle2;
  return (
    <div
      role={banner.tone === "red" ? "alert" : "status"}
      data-feed-banner={banner.tone}
      className={cn(
        "flex items-start gap-3 rounded-lg border px-4 py-3 text-sm",
        banner.tone === "red" && "border-destructive/50 bg-destructive/10 text-destructive",
        banner.tone === "amber" && "border-amber-500/40 bg-amber-500/10 text-amber-900 dark:text-amber-200",
        banner.tone === "ok" && "bg-muted/30 text-muted-foreground",
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" />
      <div className="space-y-0.5">
        <p className="font-medium">{banner.title}</p>
        <p className={cn(banner.tone === "ok" ? "" : "opacity-90")}>{banner.detail}</p>
      </div>
    </div>
  );
}

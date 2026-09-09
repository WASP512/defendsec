import { Badge } from "@/components/ui/badge";
import type { PolicyStatus } from "@/lib/types";

export function OnlineBadge({ online }: { online: boolean }) {
  return (
    <Badge variant={online ? "default" : "secondary"}>
      {online ? "Online" : "Offline"}
    </Badge>
  );
}

export function PolicyBadge({ status }: { status: PolicyStatus }) {
  if (status === "pass") return <Badge>Passing</Badge>;
  if (status === "fail") return <Badge variant="destructive">Failing</Badge>;
  return <Badge variant="outline">Unknown</Badge>;
}

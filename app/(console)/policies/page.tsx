import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, PageHeader } from "@/components/console-ui";
import { ensureStore } from "@/lib/store";
import { policySummary } from "@/lib/policies";
import { loadFleet, loadMtlsFimEvents } from "@/lib/mtls-agents";
import { ShieldQuestion } from "lucide-react";

export const dynamic = "force-dynamic";

export default async function PoliciesPage() {
  const store = await ensureStore();
  const fleet = await loadFleet(store.devices);
  const policies = policySummary(fleet, [...(await loadMtlsFimEvents()), ...store.fimEvents], store.triages);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <PageHeader
        title="Policies"
        description={
          <>
          These checks run on the last inventory snapshot. They are not CIS benchmarks, and they
          cannot remediate — they only report what the agent sent.
          </>
        }
      />
      {fleet.length === 0 ? (
        <EmptyState
          title="No policy results"
          description="Enroll a host or load the sample fleet to evaluate security checks."
          icon={ShieldQuestion}
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {policies.map((policy) => (
            <Card key={policy.id}>
              <CardHeader className="grid grid-cols-[1fr_auto] items-start gap-3">
                <CardTitle>{policy.name}</CardTitle>
                <span className={policy.failing > 0 ? "rounded-full bg-destructive/10 px-2 py-1 text-xs font-medium text-destructive" : "rounded-full bg-emerald-500/10 px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400"}>
                  {policy.failing > 0 ? "Action needed" : "Healthy"}
                </span>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p className="text-muted-foreground">{policy.description}</p>
                <div className="grid grid-cols-3 divide-x rounded-lg border bg-muted/20 py-3 text-center">
                  <div><span className="block text-lg font-semibold text-emerald-700 dark:text-emerald-400">{policy.passing}</span><span className="text-xs text-muted-foreground">passing</span></div>
                  <div><span className="block text-lg font-semibold text-destructive">{policy.failing}</span><span className="text-xs text-muted-foreground">failing</span></div>
                  <div><span className="block text-lg font-semibold">{policy.unknown}</span><span className="text-xs text-muted-foreground">unknown</span></div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

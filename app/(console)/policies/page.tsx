import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ensureStore } from "@/lib/store";
import { policySummary } from "@/lib/policies";

export const dynamic = "force-dynamic";

export default async function PoliciesPage() {
  const store = await ensureStore();
  const policies = policySummary(store.devices, store.fimEvents, store.triages);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Policies</h1>
        <p className="mt-1 max-w-2xl text-muted-foreground">
          These checks run on the last inventory snapshot. They are not CIS benchmarks, and they
          cannot remediate — they only report what the agent sent.
        </p>
      </div>
      {store.devices.length === 0 ? (
        <p className="rounded-xl border border-dashed p-10 text-center text-muted-foreground">
          Enroll a host or load the sample fleet to see policy results.
        </p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          {policies.map((policy) => (
            <Card key={policy.id}>
              <CardHeader>
                <CardTitle>{policy.name}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p className="text-muted-foreground">{policy.description}</p>
                <p>
                  <span className="font-medium">{policy.passing}</span> passing ·{" "}
                  <span className="font-medium">{policy.failing}</span> failing ·{" "}
                  <span className="font-medium">{policy.unknown}</span> unknown
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

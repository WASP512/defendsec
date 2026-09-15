import { Lock, ShieldCheck, ShieldQuestion } from "lucide-react";

import type { CryptoPosture } from "@/lib/identity";

// An assessor asking whether a deployment runs approved cryptography cannot
// answer it from configuration: Go's fips140=on routes standard-library crypto
// through the validated module but rejects nothing. This renders what the
// running control plane reports, deviations included, rather than implying a
// posture by staying silent.

export function CryptoPostureCard({
  posture,
}: {
  posture: CryptoPosture | null;
}) {
  if (!posture) {
    return (
      <section className="rounded-xl border bg-background p-5">
        <div className="flex items-center gap-2">
          <ShieldQuestion
            className="size-4 text-muted-foreground"
            aria-hidden
          />
          <h2 className="text-sm font-medium">Cryptographic posture</h2>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">
          The control plane did not report its posture. Check that
          defendsec-apid is running.
        </p>
      </section>
    );
  }

  const approved = posture.approvedAlgorithmsRequired;
  const mode = posture.goModuleEnforced
    ? "Go FIPS module, enforcing (GODEBUG=fips140=only)"
    : posture.goModuleEnabled
      ? "Go FIPS module, not enforcing (GODEBUG=fips140=on)"
      : "Go FIPS module off";

  return (
    <section className="rounded-xl border bg-background p-5">
      <div className="flex items-center gap-2">
        {approved ? (
          <ShieldCheck className="size-4 text-emerald-500" aria-hidden />
        ) : (
          <Lock className="size-4 text-muted-foreground" aria-hidden />
        )}
        <h2 className="text-sm font-medium">Cryptographic posture</h2>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        What this control plane is doing right now, not what was intended. FIPS
        140-3 setup is in the operations guide.
      </p>

      <dl className="mt-4 grid gap-3 sm:grid-cols-3">
        <div>
          <dt className="text-xs text-muted-foreground">Approved algorithms</dt>
          <dd className="text-sm font-medium">
            {approved ? "Required" : "Not required"}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Password hashing</dt>
          <dd className="font-mono text-sm">{posture.passwordKdf}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Runtime</dt>
          <dd className="text-sm">{mode}</dd>
        </div>
      </dl>

      {posture.notes && posture.notes.length > 0 ? (
        <ul className="mt-4 space-y-2 border-t pt-4 text-xs text-muted-foreground">
          {posture.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

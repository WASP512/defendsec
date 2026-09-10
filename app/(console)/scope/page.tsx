export default function ScopePage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">How hard is “our own Fleet”?</h1>
        <p className="mt-2 text-muted-foreground">
          A security-focused, self-hosted console without subscriptions is several products. Keel
          is the layer you can own immediately: agent inventory, versions, patch gaps, a local
          advisory catalog, and file integrity. It is not Apple/Windows MDM.
        </p>
      </div>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">This repo (security inventory)</h2>
        <p>
          Enroll secret, Python agent, host list, pending updates, hashed paths, snapshot
          policies, and CVE-shaped matches against <code>lib/advisories.ts</code>. No native
          modules and no vendor account.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Doable without Apple or Microsoft</h2>
        <ul className="list-disc space-y-2 pl-5 text-muted-foreground">
          <li>
            <span className="text-foreground">Real vulnerability intelligence</span> — nightly
            OSV/NVD ingest, CPE/purl matching, false-positive workflow. Data engineering more
            than UI; still fully self-hostable.
          </li>
          <li>
            <span className="text-foreground">Patch orchestration</span> — reporting is easy;
            actually installing updates needs ssh/winrm/osquery plus change windows and
            rollback. Medium-hard operations, not a protocol monopoly.
          </li>
          <li>
            <span className="text-foreground">Serious FIM</span> — inotify/FSEvents, signed
            baselines, exclusion rules, and noisy-path tuning. The hash-on-check-in model here
            is the honest first slice.
          </li>
          <li>
            <span className="text-foreground">Live queries at scale</span> — osquery (or
            similar), TLS identity, scheduling, result diffs across thousands of hosts.
          </li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">The wall: real MDM</h2>
        <p className="text-muted-foreground">
          Lock, wipe, DEP/ABM, configuration profiles, Windows MDM CSP, Android Enterprise —
          vendor protocols plus certificates from Apple, Microsoft, and Google. You cannot fully
          self-host that control plane without those relationships. Open-source Fleet still
          talks to the same APIs; premiums are mostly features and support, not a secret MDM
          unlock.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Practical split</h2>
        <p className="text-muted-foreground">
          Keep going on this agent plane for “what is on the box, is it patched, did
          sshd_config move.” Keep a real MDM beside it if you need “wipe a stolen Mac.” Do not
          try to clone all of Fleet in one product.
        </p>
      </section>
    </div>
  );
}

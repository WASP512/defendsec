export default function ScopePage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">How hard is “our own Fleet”?</h1>
        <p className="mt-2 text-muted-foreground">
          Replacing FleetDM&apos;s marketing page is easy. Replacing what Fleet does on real
          company laptops is several distinct products stacked together. Keel ships the first
          layer only.
        </p>
      </div>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">This repo (inventory plane)</h2>
        <p>
          A server, an enroll secret, an agent that POSTs facts, a host list, and snapshot
          policies. No native modules, no vendor APIs, no device control. That is the slice you
          can own without subscriptions.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Hard, but doable without Apple/Microsoft</h2>
        <ul className="list-disc space-y-2 pl-5 text-muted-foreground">
          <li>
            <span className="text-foreground">Live queries at scale</span> — an osquery (or
            similar) agent, TLS identity, query scheduling, result differential, and fan-out
            across thousands of hosts.
          </li>
          <li>
            <span className="text-foreground">Software + CVE matching</span> — normalized package
            inventory and a vulnerability feed. Data pipelines more than UI.
          </li>
          <li>
            <span className="text-foreground">Teams, SSO, audit logs</span> — ordinary product
            work, not the reason Fleet charges.
          </li>
        </ul>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">The wall: real MDM</h2>
        <p className="text-muted-foreground">
          Lock, wipe, DEP/ABM enrollment, configuration profiles, Windows MDM CSP, Android
          Enterprise — these are vendor protocols plus certificates issued by Apple, Microsoft,
          and Google. You cannot fully self-host that control plane without those relationships.
          Open-source Fleet still talks to those same APIs; the premium line is mostly around
          features and support on top, not a magic unlock of MDM itself.
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-semibold">Practical split</h2>
        <p className="text-muted-foreground">
          If the goal is “see every machine, ask questions, enforce a few settings we can
          observe,” keep building on this agent model. If the goal is “wipe a stolen Mac from
          the internet,” you need an MDM server (or keep using Fleet/MicroMDM/Nudge/Intune for
          that plane) rather than cloning the whole product.
        </p>
      </section>
    </div>
  );
}

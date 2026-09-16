import {
  categoryRows,
  orderedLevels,
  type DetectionCoverage,
  type ForwardingStatus,
} from "@/lib/detection";

// The detection coverage view (roadmap 3.4).
//
// A coverage matrix made of green squares is a marketing asset. The useful
// half is the part that says what DefendSec cannot see, so this page leads
// with blind spots — rules that cannot fire because nothing reports their
// event kind, rules that failed to load, and hosts that dropped events — and
// only then shows what is covered.
//
// There is also no coverage percentage anywhere on this page. ATT&CK has no
// fixed denominator, and a rule covers a behaviour rather than a technique;
// any percentage would be a number we made up.

function Pill({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "neutral" | "good" | "warning" | "bad";
}) {
  const tones = {
    neutral: "border-border bg-muted text-muted-foreground",
    good: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    warning:
      "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
    bad: "border-destructive/40 bg-destructive/10 text-destructive",
  };
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-[11px] ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

function Section({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border bg-background p-5">
      <h2 className="text-sm font-medium">{title}</h2>
      {hint ? (
        <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
      ) : null}
      <div className="mt-4">{children}</div>
    </section>
  );
}

function Caveats({ caveats }: { caveats: string[] }) {
  if (caveats.length === 0) return null;
  return (
    <section className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-5">
      <h2 className="text-sm font-medium">What this page does not tell you</h2>
      <ul className="mt-3 space-y-2 text-sm">
        {caveats.map((caveat) => (
          <li key={caveat} className="flex gap-2">
            <span aria-hidden className="text-amber-600 dark:text-amber-400">
              &bull;
            </span>
            <span>{caveat}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function EventKinds({ coverage }: { coverage: DetectionCoverage }) {
  const rows = categoryRows(coverage);
  return (
    <Section
      title="Event kinds"
      hint="A rule can only fire on an event kind some sensor actually reports. Kinds with rules but no observations are listed first — those rules are not running, whatever the technique list below says."
    >
      <ul className="divide-y">
        {rows.map((row) => {
          const dead = row.rules > 0 && !row.observed;
          const unwatched = row.rules === 0 && row.observed;
          return (
            <li
              key={row.category}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5"
            >
              <code className="text-xs">{row.category}</code>
              <span className="text-sm text-muted-foreground">
                {row.rules === 1 ? "1 rule" : `${row.rules} rules`}
              </span>
              {dead ? (
                <Pill tone="bad">no sensor reports this kind</Pill>
              ) : null}
              {unwatched ? (
                <Pill tone="warning">observed, no rules</Pill>
              ) : null}
              {!dead && !unwatched && row.rules === 0 ? (
                <Pill>no rules, not observed</Pill>
              ) : null}
              {row.observed && row.rules > 0 ? (
                <Pill tone="good">live</Pill>
              ) : null}
            </li>
          );
        })}
      </ul>
    </Section>
  );
}

function SkippedRules({ coverage }: { coverage: DetectionCoverage }) {
  const skipped = coverage.skipped ?? [];
  if (skipped.length === 0) return null;
  return (
    <Section
      title="Rules that failed to load"
      hint="These are not running. A rule directory is usually a synced community repository, so an unsupported feature is skipped rather than refusing to start — but a skipped rule is a silent gap unless it is named."
    >
      <ul className="divide-y">
        {skipped.map((rule) => (
          <li key={`${rule.source}:${rule.reason}`} className="space-y-1 py-2.5">
            <code className="block text-xs break-all">{rule.source}</code>
            <p className="text-sm text-muted-foreground">{rule.reason}</p>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function Gaps({ coverage }: { coverage: DetectionCoverage }) {
  const entries = Object.entries(coverage.gaps ?? {});
  if (entries.length === 0) return null;
  const lossy = entries.filter(([, gap]) => gap.droppedTotal > 0);
  lossy.sort((a, b) => b[1].droppedTotal - a[1].droppedTotal);
  const clean = entries.length - lossy.length;

  return (
    <Section
      title="Event loss by host"
      hint="The agent's buffer drops events rather than blocking the sensor, because a host that stops being defended in order to keep its telemetry tidy has the trade-off backwards. Detection over a dropped window is incomplete."
    >
      {lossy.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No host has reported dropped events.{" "}
          {clean === 1 ? "1 host is" : `${clean} hosts are`} streaming.
        </p>
      ) : (
        <ul className="divide-y">
          {lossy.map(([deviceId, gap]) => (
            <li
              key={deviceId}
              className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2.5"
            >
              <span className="text-sm font-medium">
                {gap.hostname || deviceId}
              </span>
              {gap.hostname ? (
                <code className="text-xs text-muted-foreground">
                  {deviceId}
                </code>
              ) : null}
              <span className="text-sm text-destructive">
                {gap.droppedTotal.toLocaleString()} dropped
              </span>
              <span className="text-sm text-muted-foreground">
                {gap.received.toLocaleString()} received
                {gap.sensor ? ` · ${gap.sensor}` : null}
                {gap.lastGapAt
                  ? ` · last gap ${new Date(gap.lastGapAt).toISOString().replace("T", " ").slice(0, 19)}Z`
                  : null}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Techniques({ coverage }: { coverage: DetectionCoverage }) {
  return (
    <Section
      title="ATT&CK techniques with at least one rule"
      hint="A technique listed here has a rule. It does not mean every way of performing it is detected — techniques are broad, and a rule covers a behaviour. There is no percentage here on purpose: ATT&CK has no denominator that would make one honest."
    >
      {coverage.techniques.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No loaded rule carries an ATT&CK technique tag.
        </p>
      ) : (
        <>
          {coverage.tactics.length > 0 ? (
            <div className="mb-3 flex flex-wrap gap-1.5">
              {coverage.tactics.map((tactic) => (
                <Pill key={tactic}>{tactic}</Pill>
              ))}
            </div>
          ) : null}
          <div className="flex flex-wrap gap-1.5">
            {coverage.techniques.map((technique) => (
              <a
                key={technique}
                href={`https://attack.mitre.org/techniques/${technique.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                className="rounded border px-1.5 py-0.5 font-mono text-[11px] hover:bg-muted"
              >
                {technique}
              </a>
            ))}
          </div>
        </>
      )}
    </Section>
  );
}

function Forwarding({ status }: { status: ForwardingStatus }) {
  return (
    <Section
      title="Forwarding"
      hint="DefendSec keeps a short event window for alert context. It is not a log store, and it does not pretend to be one — history belongs in the platform you already run."
    >
      <p className="text-sm">{status.detail}</p>
      {status.enabled ? (
        <>
          <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
            {[
              ["Accepted", status.accepted],
              ["Sent", status.sent],
              ["Failed", status.failed],
              ["Dropped", status.dropped],
            ].map(([label, value]) => (
              <div key={String(label)}>
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd
                  className={
                    (label === "Dropped" || label === "Failed") &&
                    Number(value) > 0
                      ? "text-destructive"
                      : undefined
                  }
                >
                  {Number(value).toLocaleString()}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-muted-foreground">
            Queue {status.queued.toLocaleString()} of{" "}
            {status.capacity.toLocaleString()}.
          </p>
          {status.destinations && status.destinations.length > 0 ? (
            <ul className="mt-4 divide-y border-t">
              {status.destinations.map((d) => (
                <li
                  key={d.name}
                  className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2.5"
                >
                  <code className="text-xs break-all">{d.name}</code>
                  {d.healthy ? (
                    <Pill tone="good">healthy</Pill>
                  ) : (
                    <Pill tone="bad">failing</Pill>
                  )}
                  <span className="text-sm text-muted-foreground">
                    {d.sent.toLocaleString()} sent
                    {d.failed > 0 ? `, ${d.failed.toLocaleString()} failed` : ""}
                  </span>
                  {d.lastError ? (
                    <span className="w-full text-xs text-destructive">
                      {d.lastError}
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}
    </Section>
  );
}

export function DetectionView({
  coverage,
  forwarding,
}: {
  coverage: DetectionCoverage;
  forwarding: ForwardingStatus | null;
}) {
  const levels = orderedLevels(coverage.byLevel);
  return (
    <div className="space-y-6">
      <Caveats caveats={coverage.caveats} />

      <Section
        title="Rules in force"
        hint="Loaded from the Sigma rule directory at start-up. A rule that is not listed here is not running."
      >
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-2">
          <span className="text-3xl font-semibold tracking-tight">
            {coverage.rules.toLocaleString()}
          </span>
          <span className="text-sm text-muted-foreground">
            {coverage.rules === 1 ? "rule loaded" : "rules loaded"}
          </span>
          {coverage.skipped && coverage.skipped.length > 0 ? (
            <Pill tone="bad">{coverage.skipped.length} failed to load</Pill>
          ) : null}
        </div>
        {levels.length > 0 ? (
          <div className="mt-4 flex flex-wrap gap-1.5">
            {levels.map(({ level, count }) => (
              <Pill
                key={level}
                tone={
                  level === "critical" || level === "high"
                    ? "bad"
                    : level === "medium"
                      ? "warning"
                      : "neutral"
                }
              >
                {level} {count}
              </Pill>
            ))}
          </div>
        ) : null}
      </Section>

      <EventKinds coverage={coverage} />
      <SkippedRules coverage={coverage} />
      <Gaps coverage={coverage} />
      <Techniques coverage={coverage} />
      {forwarding ? <Forwarding status={forwarding} /> : null}
    </div>
  );
}

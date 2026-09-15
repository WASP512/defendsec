import { Anchor, ShieldAlert, ShieldCheck } from "lucide-react";

import type { AnchorStatus } from "@/lib/compliance";

// Transparency anchoring (roadmap 1.6).
//
// This panel shows the *comparison*, not a count of anchors written. A number
// of anchors published proves nothing; whether they still match the chain is
// the only question worth asking, and it is the one a compromised server
// cannot answer in its own favour.

const KIND_LABEL: Record<string, string> = {
  rfc3161: "Timestamp authority",
  file: "File / git",
  peer: "Peer instance",
};

export function AnchorPanel({ status }: { status: AnchorStatus | null }) {
  if (!status) {
    return (
      <section className="rounded-xl border bg-background p-5">
        <div className="flex items-center gap-2">
          <Anchor className="size-4 text-muted-foreground" aria-hidden />
          <h2 className="text-sm font-medium">Transparency anchoring</h2>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">
          Anchor status is unavailable. The control plane may be unreachable, or
          no database is configured.
        </p>
      </section>
    );
  }

  const broken = status.summary.mismatched > 0 || status.summary.missing > 0;
  const clean = !broken && status.summary.matching > 0;

  return (
    <section
      className={`rounded-xl border p-5 ${
        broken ? "border-destructive/50 bg-destructive/5" : "bg-background"
      }`}
    >
      <div className="flex items-center gap-2">
        {broken ? (
          <ShieldAlert className="size-4 text-destructive" aria-hidden />
        ) : clean ? (
          <ShieldCheck className="size-4 text-emerald-500" aria-hidden />
        ) : (
          <Anchor className="size-4 text-muted-foreground" aria-hidden />
        )}
        <h2 className="text-sm font-medium">Transparency anchoring</h2>
      </div>

      <p
        className={`mt-2 text-sm ${broken ? "text-destructive" : "text-muted-foreground"}`}
      >
        {status.summary.verdict}
      </p>

      {status.targets.length > 0 ? (
        <dl className="mt-4 space-y-1 text-xs">
          {status.targets.map((t) => (
            <div key={`${t.kind}:${t.target}`} className="flex gap-2">
              <dt className="w-36 shrink-0 text-muted-foreground">
                {KIND_LABEL[t.kind] ?? t.kind}
              </dt>
              <dd className="truncate font-mono">{t.target}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground">
          No anchor targets configured. Set{" "}
          <code>DEFENDSEC_ANCHOR_TARGETS</code> to publish checkpoints somewhere
          this server cannot reach back and change.
        </p>
      )}

      {status.verifications.length > 0 ? (
        <ul className="mt-4 space-y-2 border-t pt-4 text-xs">
          {status.verifications.slice(0, 10).map((v) => (
            <li key={v.record.id} className="flex gap-2">
              <span
                className={`mt-0.5 size-2 shrink-0 rounded-full ${
                  !v.record.error && v.matches
                    ? "bg-emerald-500"
                    : v.record.error
                      ? "bg-muted-foreground"
                      : "bg-destructive"
                }`}
                aria-hidden
              />
              <span className="text-muted-foreground">
                <span className="text-foreground">
                  seq {v.record.throughSeq}
                </span>{" "}
                <span className="opacity-70">
                  ({KIND_LABEL[v.record.kind] ?? v.record.kind})
                </span>{" "}
                — {v.detail}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {status.peerAnchors.length > 0 ? (
        <p className="mt-4 border-t pt-4 text-xs text-muted-foreground">
          Holding {status.peerAnchors.length} checkpoint
          {status.peerAnchors.length === 1 ? "" : "s"} for peer instances. These
          are somebody else&rsquo;s evidence, kept separately from this
          instance&rsquo;s own.
        </p>
      ) : null}
    </section>
  );
}

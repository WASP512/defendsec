import Link from "next/link";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { surfaceChart, trendChart, trendHref, trendSummary, TREND_WINDOWS, type ExposureTrend, type TrendQuery } from "@/lib/exposure-model";
import { surfaceTrendSummary } from "@/lib/surface-exposure";
import { identityTrendSummary } from "@/lib/identity-exposure";
import type { AuditPeriod } from "@/lib/compliance";
import { cn } from "@/lib/utils";

function surfaceTitle(points: ExposureTrend["points"], day: string): string {
  const p = points.find((x) => x.day === day);
  if (!p || !p.surfaceKnown) return "";
  return `, ${p.surface ?? 0} external (${p.surfaceHigh ?? 0} high or critical)`;
}

const WIDTH = 720;
const HEIGHT = 140;
const SURFACE_HEIGHT = 60;

function Choice({ href, active, children }: { href: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      aria-current={active ? "true" : undefined}
      className={cn(
        "rounded-md border px-2.5 py-1 text-xs",
        active ? "border-primary bg-primary/10 font-medium" : "text-muted-foreground hover:bg-muted",
      )}
    >
      {children}
    </Link>
  );
}

/**
 * Open findings over time, a bar per day (the KEV share in red) and the
 * nothing-to-install count as a dashed line. The window is a number of days or
 * an audit period, so "is it getting better?" can be asked of a quarter.
 */
export function ExposureTrendCard({
  trend,
  query,
  periods,
}: {
  trend: ExposureTrend | null;
  query: TrendQuery;
  periods: AuditPeriod[];
}) {
  const chart = trend ? trendChart(trend.points, WIDTH, HEIGHT) : null;
  const sChart = trend ? surfaceChart(trend.points, WIDTH, SURFACE_HEIGHT) : null;
  const first = trend?.points[0]?.day;
  const last = trend?.points[trend.points.length - 1]?.day;
  return (
    <Card data-exposure-trend>
      <CardHeader>
        <CardTitle className="text-lg">Is it getting better?</CardTitle>
        <CardDescription>
          {trend ? trendSummary(trend.points) : "The trend is unavailable: the control plane could not be reached."}
          {trend ? (
            <span className="block" data-surface-trend-summary>
              {surfaceTrendSummary(trend.points, trend.surfaceSince)}
            </span>
          ) : null}
          {trend ? (
            <span className="block" data-identity-trend-summary>
              {identityTrendSummary(trend.points, trend.identitySince)}
            </span>
          ) : null}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2" aria-label="Trend window">
          {TREND_WINDOWS.map((d) => (
            <Choice key={d} href={trendHref({ days: d })} active={!query.periodId && query.days === d}>
              {d} days
            </Choice>
          ))}
          {periods.slice(0, 6).map((p) => (
            <Choice key={p.id} href={trendHref({ periodId: p.id })} active={query.periodId === p.id}>
              {p.name}
              {p.closedAt ? " (closed)" : ""}
            </Choice>
          ))}
        </div>
        {trend && chart ? (
          <>
            {trend.period ? (
              <p className="text-xs text-muted-foreground">
                Audit period {trend.period.name}: {first} to {last}
                {trend.period.closed ? ", closed" : ", still open"}.
              </p>
            ) : null}
            <svg
              viewBox={`0 0 ${WIDTH} ${HEIGHT + 4}`}
              role="img"
              aria-label={trendSummary(trend.points)}
              className="h-40 w-full"
              preserveAspectRatio="none"
            >
              <line x1="0" y1={HEIGHT} x2={WIDTH} y2={HEIGHT} className="stroke-border" />
              {chart.bars.map((b) =>
                b.known ? (
                  <g key={b.day}>
                    <title>{`${b.day}: ${b.open} open (${b.kev} on KEV), ${b.watch} nothing to install${surfaceTitle(trend.points, b.day)}`}</title>
                    <rect x={b.x} y={HEIGHT - b.openHeight} width={b.width} height={b.openHeight} className="fill-primary/60" />
                    <rect x={b.x} y={HEIGHT - b.kevHeight} width={b.width} height={b.kevHeight} className="fill-red-600" />
                  </g>
                ) : (
                  <g key={b.day}>
                    <title>{`${b.day}: no data (before the first feed snapshot)`}</title>
                    <rect x={b.x} y={HEIGHT - 3} width={b.width} height={3} className="fill-muted-foreground/40" />
                  </g>
                ),
              )}
              {chart.watchPoints ? (
                <polyline
                  points={chart.watchPoints}
                  fill="none"
                  strokeWidth="2"
                  strokeDasharray="5 4"
                  className="stroke-amber-500"
                />
              ) : null}
            </svg>
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{first}</span>
              <span>max {chart.max}</span>
              <span>{last}</span>
            </div>
            {sChart && sChart.bars.some((b) => b.known) ? (
              <div className="space-y-1" data-surface-trend>
                <p className="text-xs font-medium">External surface findings open (its own scale, max {sChart.max})</p>
                <svg
                  viewBox={`0 0 ${WIDTH} ${SURFACE_HEIGHT + 4}`}
                  role="img"
                  aria-label={surfaceTrendSummary(trend.points, trend.surfaceSince)}
                  className="h-20 w-full"
                  preserveAspectRatio="none"
                >
                  <line x1="0" y1={SURFACE_HEIGHT} x2={WIDTH} y2={SURFACE_HEIGHT} className="stroke-border" />
                  {sChart.bars.map((b) =>
                    b.known ? (
                      <g key={b.day}>
                        <title>{`${b.day}: ${b.surface} external surface findings open (${b.high} critical or high)`}</title>
                        <rect x={b.x} y={SURFACE_HEIGHT - b.height} width={b.width} height={b.height} className="fill-sky-600/70" />
                        <rect x={b.x} y={SURFACE_HEIGHT - b.highHeight} width={b.width} height={b.highHeight} className="fill-red-600" />
                      </g>
                    ) : (
                      <g key={b.day}>
                        <title>{`${b.day}: no data (before the first surface scan)`}</title>
                        <rect x={b.x} y={SURFACE_HEIGHT - 3} width={b.width} height={3} className="fill-muted-foreground/40" />
                      </g>
                    ),
                  )}
                </svg>
              </div>
            ) : null}
            <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <li>
                <span className="mr-1 inline-block size-2.5 rounded-sm bg-primary/60 align-middle" />
                open, with a fix
              </li>
              <li>
                <span className="mr-1 inline-block size-2.5 rounded-sm bg-red-600 align-middle" />
                of which on KEV
              </li>
              <li>
                <span className="mr-1 inline-block h-0.5 w-4 border-t-2 border-dashed border-amber-500 align-middle" />
                nothing to install yet
              </li>
              <li>
                <span className="mr-1 inline-block size-2.5 rounded-sm bg-sky-600/70 align-middle" />
                external surface findings open (red: critical or high)
              </li>
              <li>
                <span className="mr-1 inline-block h-0.5 w-4 bg-muted-foreground/40 align-middle" />
                no data
              </li>
            </ul>
            <ul className="space-y-0.5 text-xs text-muted-foreground">
              {trend.caveats.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}

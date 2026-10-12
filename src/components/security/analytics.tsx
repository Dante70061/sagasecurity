import { useState } from "react";
import { Activity, Database, Fingerprint, Globe, ChevronDown } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Button } from "@/components/ui/button";
import type { LogView } from "@/data/log-summary";

const NAMED_SLICE_COLORS = [
  "var(--primary)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--warning)",
];

function sliceColor(name: string, namedIndex: number): { color: string; nextNamed: number } {
  if (name === "Other") return { color: "var(--muted-foreground)", nextNamed: namedIndex };
  return { color: NAMED_SLICE_COLORS[namedIndex % NAMED_SLICE_COLORS.length], nextNamed: namedIndex + 1 };
}

export function SecurityMetrics({ view }: { view: LogView }) {
  const metrics = [
    {
      label: "Events in file",
      value: view.events.toLocaleString("en-US"),
      icon: Activity,
    },
    {
      label: "Log files",
      value: view.logFiles.toLocaleString("en-US"),
      icon: Database,
    },
    {
      label: "Unique IP addresses",
      value: view.srcIps.toLocaleString("en-US"),
      icon: Globe,
    },
    {
      label: "Identities observed",
      value: view.identities.length.toLocaleString("en-US"),
      icon: Fingerprint,
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {metrics.map(({ label, value, icon: Icon }) => (
        <article className="panel metric-card" key={label}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">{label}</span>
            <Icon className="size-4 text-muted-foreground" />
          </div>
          <div className="mt-1">
            <span className="metric-number">{value}</span>
          </div>
        </article>
      ))}
    </div>
  );
}

export function SecurityAnalytics({ view }: { view: LogView }) {
  const [range, setRange] = useState("24h");
  const data = range === "24h" ? view.hours : view.days;
  const dayLabel = `${view.days.length}d`;
  let namedSlice = 0;
  const slices = view.distribution.map((row) => {
    const colored = sliceColor(row.name, namedSlice);
    namedSlice = colored.nextNamed;
    return { ...row, color: colored.color };
  });
  return (
    <div className="analytics-column focus-section" id="analytics">
      <section className="panel">
        <div className="panel-heading">
          <div className="flex items-center gap-2.5">
            <Activity className="size-4 text-primary" />
            <h2>Activity overview</h2>
          </div>
        </div>
        <div className="flex items-center justify-between px-5 pt-4">
          <div>
            <p className="text-xs text-muted-foreground">Event volume over time</p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              {range === "24h" ? "Last 24 hours of this file" : "Each day in this file"}
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">{view.spanLabel}</p>
          </div>
          <div className="flex rounded-md border border-border p-0.5">
            {[
              { id: "24h", label: "24h" },
              { id: "days", label: dayLabel },
            ].map((option) => (
              <Button
                key={option.id}
                size="sm"
                variant={range === option.id ? "secondary" : "ghost"}
                aria-pressed={range === option.id}
                onClick={() => setRange(option.id)}
                className="h-6 px-2.5 text-[10px]"
              >
                {option.label}
              </Button>
            ))}
          </div>
        </div>
        <div className="chart-box" role="img" aria-label={`Event counts from the merged log for ${range}`}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="event-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 5" vertical={false} />
              <XAxis
                dataKey="time"
                stroke="var(--muted-foreground)"
                axisLine={false}
                tickLine={false}
                fontSize={10}
                interval={range === "24h" ? 2 : 0}
                dy={9}
              />
              <YAxis
                stroke="var(--muted-foreground)"
                axisLine={false}
                tickLine={false}
                fontSize={10}
                tickCount={4}
              />
              <Tooltip
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <div className="chart-tooltip">
                      <strong>{label}</strong>
                      {payload.map((p) => (
                        <p key={String(p.dataKey)}>
                          {p.name}: {p.value}
                        </p>
                      ))}
                    </div>
                  ) : null
                }
              />
              <Area
                type="monotone"
                dataKey="baseline"
                name="Baseline-tagged"
                stroke="var(--chart-2)"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                fill="transparent"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="events"
                name="Events"
                stroke="var(--primary)"
                strokeWidth={2}
                fill="url(#event-fill)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="flex justify-center gap-5 pb-5 pt-2 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-2">
            <span className="h-0.5 w-3 bg-primary" />
            Event volume
          </span>
          <span className="flex items-center gap-2">
            <span className="w-3 border-t border-dashed border-muted-foreground" />
            Baseline-tagged
          </span>
        </div>
      </section>
      <section className="panel flex-1" aria-label="Event distribution">
        <div className="panel-heading">
          <div className="flex items-center gap-2.5">
            <Database className="size-4 text-primary" />
            <h2>Event distribution</h2>
          </div>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-muted-foreground">Every row in this file</p>
          <p className="mt-1 text-[11px] text-muted-foreground">{view.spanLabel}</p>
          <div className="mt-4 flex items-center gap-5">
            <div
              className="source-chart"
              role="img"
              aria-label={slices.map((row) => `${row.name} ${row.share}%`).join(", ")}
            >
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={slices}
                    dataKey="count"
                    nameKey="name"
                    innerRadius={46}
                    outerRadius={62}
                    paddingAngle={2}
                    stroke="none"
                    startAngle={90}
                    endAngle={-270}
                    isAnimationActive={false}
                  >
                    {slices.map((row) => (
                      <Cell key={row.name} fill={row.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-sm font-semibold">{view.events.toLocaleString("en-US")}</span>
                <span className="mt-0.5 text-[10px] text-muted-foreground">events</span>
              </div>
            </div>
            <div className="min-w-0 flex-1 space-y-3">
              {slices.map((row) => (
                <div className="flex items-baseline justify-between gap-3 text-xs" key={row.name}>
                  <span className="flex min-w-0 items-center gap-2 text-muted-foreground">
                    <span className="size-1.5 shrink-0 rounded-full" style={{ background: row.color }} />
                    <span className="truncate" title={row.name}>
                      {row.name}
                    </span>
                  </span>
                  <span className="shrink-0 font-mono text-[11px]">
                    {row.count.toLocaleString("en-US")} · {row.share}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

export function PeriodSelector() {
  const [period, setPeriod] = useState("Last 24 hours");
  return (
    <div className="relative">
      <select
        aria-label="Demo analytics period"
        value={period}
        onChange={(e) => setPeriod(e.target.value)}
        className="h-9 appearance-none rounded-md border border-border bg-card py-2 pl-3 pr-9 text-xs text-secondary-foreground focus:outline-none focus:ring-1 focus:ring-primary"
      >
        <option>Last 24 hours</option>
        <option>Last 7 days</option>
      </select>
      <ChevronDown className="pointer-events-none absolute right-3 top-3 size-3 text-muted-foreground" />
    </div>
  );
}

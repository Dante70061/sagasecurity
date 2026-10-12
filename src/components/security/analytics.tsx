import { useState } from "react";
import { Activity, ArrowUpRight, Database, Fingerprint, Globe, ChevronDown } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { Button } from "@/components/ui/button";
import type { LogView } from "@/data/log-summary";

export function SecurityMetrics({ view }: { view: LogView }) {
  const metrics = [
    {
      label: "Events in file",
      value: view.events.toLocaleString("en-US"),
      change: view.eventChange,
      detail: "vs prior 24h in this file",
      icon: Activity,
    },
    {
      label: "Log files",
      value: view.logFiles.toLocaleString("en-US"),
      change: `${view.collectors.length} collectors`,
      detail: view.collectors.join(" · "),
      icon: Database,
    },
    {
      label: "Unique IP addresses",
      value: view.srcIps.toLocaleString("en-US"),
      change: view.ipChange,
      detail: "src and dst fields",
      icon: Globe,
    },
    {
      label: "Identities observed",
      value: view.identities.length.toLocaleString("en-US"),
      change: "Parsed from raw lines",
      detail: view.identities.join(", ") || "none",
      icon: Fingerprint,
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
      {metrics.map(({ label, value, change, detail, icon: Icon }) => (
        <article className="panel metric-card" key={label}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">{label}</span>
            <Icon className="size-4 text-muted-foreground" />
          </div>
          <div className="mt-2 flex items-center justify-between gap-2">
            <span className="metric-number">{value}</span>
            <span className="demo-badge">FILE</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
            <span className={change.startsWith("+") ? "text-success" : "text-primary"}>
              {change.startsWith("+") && <ArrowUpRight className="mr-0.5 inline size-3" />}
              {change}
            </span>
            <span className="text-muted-foreground">{detail}</span>
          </div>
        </article>
      ))}
    </div>
  );
}

export function SecurityAnalytics({ view }: { view: LogView }) {
  const [range, setRange] = useState("24h");
  const data = range === "24h" ? view.hours : view.days;
  return (
    <div className="analytics-column focus-section" id="analytics">
      <section className="panel">
        <div className="panel-heading">
          <div className="flex items-center gap-2.5">
            <Activity className="size-4 text-primary" />
            <h2>Activity overview</h2>
          </div>
          <span className="demo-badge">MERGED LOG</span>
        </div>
        <div className="flex items-center justify-between px-5 pt-4">
          <div>
            <p className="text-xs text-muted-foreground">Event volume over time</p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              {range === "24h" ? "Last 24 hours of this file" : "Each day in this file"}
            </p>
          </div>
          <div className="flex rounded-md border border-border p-0.5">
            {["24h", "7d"].map((r) => (
              <Button
                key={r}
                size="sm"
                variant={range === r ? "secondary" : "ghost"}
                aria-pressed={range === r}
                onClick={() => setRange(r)}
                className="h-6 px-2.5 text-[10px]"
              >
                {r}
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
                name="Baseline-flagged"
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
            Baseline-flagged
          </span>
        </div>
      </section>
      <section className="panel flex-1">
        <div className="panel-heading">
          <div className="flex items-center gap-2.5">
            <Database className="size-4 text-primary" />
            <h2>Event distribution</h2>
          </div>
          <span className="demo-badge">MERGED LOG</span>
        </div>
        <div className="flex items-center justify-center gap-7 px-5 py-6">
          <div
            className="source-chart"
            role="img"
            aria-label={view.distribution.map((s) => `${s.name} ${s.percent}%`).join(", ")}
          >
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={view.distribution}
                  dataKey="count"
                  innerRadius={53}
                  outerRadius={66}
                  paddingAngle={4}
                  stroke="none"
                  startAngle={90}
                  endAngle={-270}
                  isAnimationActive={false}
                >
                  {view.distribution.map((s) => (
                    <Cell key={s.name} fill={s.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-xl font-semibold">{view.events.toLocaleString("en-US")}</span>
              <span className="mt-1 text-[10px] text-muted-foreground">Rows in file</span>
            </div>
          </div>
          <div className="min-w-0 flex-1 space-y-4">
            {view.distribution.map((s) => (
              <div className="flex items-center justify-between gap-2 text-xs" key={s.name}>
                <span className="flex items-center gap-2.5 text-muted-foreground">
                  <span className="size-1.5 rounded-full" style={{ background: s.color }} />
                  {s.name}
                </span>
                <span className="font-mono text-[11px]">{s.percent}%</span>
              </div>
            ))}
          </div>
        </div>
        <div className="border-t border-border px-5 py-3 text-[11px] text-muted-foreground">
          Grouped from the location path · {view.file}
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

// Console charts. Every number comes from QueueView (incidents_scored.json + scenario_summary.json)
// except the ablation panel, whose constants cite outputs/ablation/README.md.

import { Link } from "@tanstack/react-router";
import { Cell, Pie, PieChart } from "recharts";
import { ABLATION_ARMS, ABLATION_NOTE, ABLATION_SOURCE } from "@/data/ablation";
import type { QueueView, RankedIncident, SensorCounts } from "@/data/incidents";
import { clockUtc, shortLabel } from "@/data/triage";

const n = (v: number) => v.toLocaleString("en-US");

const SENSORS: { key: keyof SensorCounts; label: string; color: string }[] = [
  { key: "wazuh", label: "Wazuh", color: "var(--sensor-wazuh)" },
  { key: "suricata", label: "Suricata", color: "var(--sensor-suricata)" },
  { key: "aminer", label: "AMiner", color: "var(--sensor-aminer)" },
];

// ------------------------------------------------------------------ funnel

function busiestDay(incidents: RankedIncident[]): { day: string; count: number } | null {
  const counts = new Map<string, number>();
  for (const i of incidents)
    counts.set(i.start.slice(0, 10), (counts.get(i.start.slice(0, 10)) ?? 0) + 1);
  const best = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0];
  return best ? { day: best[0], count: best[1] } : null;
}

export function FunnelTiles({ view }: { view: QueueView }) {
  const s = view.summary;
  const confirmed = view.incidents.filter((i) => i.group === "confirmed");
  const peak = busiestDay(confirmed);
  const tiles = [
    {
      label: "Raw alerts",
      value: s?.raw_alerts != null ? n(s.raw_alerts) : "—",
      hint: "Wazuh · Suricata · AMiner",
    },
    {
      label: "After cleanup",
      value: s ? n(s.alerts) : "—",
      hint: "duplicates and known-benign rules removed",
    },
    {
      label: "Incidents",
      value: n(view.counts.incidents),
      hint: "anomalous minutes merged by host or source IP",
    },
    {
      label: "Confirmed by model",
      value: n(view.counts.confirmed),
      hint: peak ? `p_attack ≥ 0.5 · ${peak.count} on ${peak.day.slice(5)}` : "p_attack ≥ 0.5",
      accent: true,
    },
  ];
  return (
    <section aria-label="Alert funnel" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {tiles.map((t) => (
        <div key={t.label} className={`tile ${t.accent ? "tile-accent" : ""}`}>
          <div
            className="tile-label"
            style={t.accent ? { color: "var(--brand-accent)" } : undefined}
          >
            {t.label}
          </div>
          <div className="tile-value">{t.value}</div>
          <div className="mt-1.5 text-xs text-muted-foreground">{t.hint}</div>
        </div>
      ))}
    </section>
  );
}

// ------------------------------------------------------------------ attack window timeline

export function AttackTimeline({ view }: { view: QueueView }) {
  const confirmed = view.incidents.filter((i) => i.group === "confirmed");
  const peak = busiestDay(confirmed);
  if (!peak) return null;
  const onDay = confirmed
    .filter((i) => i.start.startsWith(peak.day))
    .sort((a, b) => Date.parse(a.start) - Date.parse(b.start));
  const others = confirmed.filter((i) => !i.start.startsWith(peak.day));
  const t0 = Math.min(...onDay.map((i) => Date.parse(i.start))) - 10 * 60_000;
  const t1 = Math.max(...onDay.map((i) => Date.parse(i.end))) + 10 * 60_000;
  const pct = (t: number) => ((t - t0) / (t1 - t0)) * 100;
  const date = new Date(peak.day).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  });
  return (
    <section aria-labelledby="timeline-title" className="card px-6 py-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="timeline-title" className="section-title">
          Attack window · {date} (UTC)
        </h2>
        <span className="text-xs text-muted-foreground">confirmed incidents in time order</span>
      </div>
      <div
        className="relative mt-4 h-14"
        role="img"
        aria-label={`Confirmed incidents on ${date}: ${onDay.map((i) => `${i.incident_id} at ${clockUtc(i.start).slice(6)}`).join(", ")}`}
      >
        <div className="absolute inset-x-0 top-7 h-px bg-[#2a3352]" />
        {onDay.map((i) => {
          const left = pct(Date.parse(i.start));
          const width = Math.max(0.6, pct(Date.parse(i.end)) - left);
          return (
            <div
              key={i.incident_id}
              title={`${i.incident_id} · ${clockUtc(i.start)} to ${clockUtc(i.end)} UTC`}
              className="absolute top-[22px] h-[14px] rounded-md"
              style={{
                left: `${left}%`,
                width: `${width}%`,
                background: i.kind === "actor" ? "var(--brand-accent)" : "var(--primary)",
                opacity: 0.85,
              }}
            />
          );
        })}
        <span className="num absolute left-0 top-0 text-[11px] text-[#7c86a3]">
          {clockUtc(new Date(t0).toISOString()).slice(6)}
        </span>
        <span className="num absolute right-0 top-0 text-[11px] text-[#7c86a3]">
          {clockUtc(new Date(t1).toISOString()).slice(6)}
        </span>
      </div>
      <ol className="mt-2 grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2 xl:grid-cols-3">
        {onDay.map((i) => (
          <li key={i.incident_id} className="flex items-baseline gap-2">
            <span className="num text-foreground">{clockUtc(i.start).slice(6)}</span>
            <Link
              to="/incident/$id"
              params={{ id: i.incident_id }}
              search={{ run: view.run }}
              className="num text-primary hover:underline"
            >
              {i.incident_id}
            </Link>
            <span className="truncate text-muted-foreground">{shortLabel(i)}</span>
          </li>
        ))}
      </ol>
      {others.length > 0 && (
        <p className="mt-3 text-xs text-muted-foreground">
          Also confirmed on other days:{" "}
          {others.map((i) => `${i.incident_id} (${clockUtc(i.start)})`).join(", ")}.
        </p>
      )}
    </section>
  );
}

// ------------------------------------------------------------------ donuts

function Donut({
  data,
  center,
  sub,
  label,
}: {
  data: { name: string; value: number; color: string }[];
  center: string;
  sub: string;
  label: string;
}) {
  return (
    <div className="relative" role="img" aria-label={label}>
      <PieChart width={140} height={140}>
        <Pie
          data={data}
          dataKey="value"
          cx={65}
          cy={65}
          innerRadius={44}
          outerRadius={60}
          paddingAngle={2}
          stroke="none"
          startAngle={90}
          endAngle={-270}
          isAnimationActive={false}
        >
          {data.map((d) => (
            <Cell key={d.name} fill={d.color} />
          ))}
        </Pie>
      </PieChart>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="num text-base">{center}</span>
        <span className="text-[10px] text-muted-foreground">{sub}</span>
      </div>
    </div>
  );
}

function Legend({
  rows,
}: {
  rows: { name: string; value: string; color: string; outline?: boolean }[];
}) {
  return (
    <div className="flex flex-col gap-2.5 text-[13px]">
      {rows.map((r) => (
        <div key={r.name} className="flex items-center gap-2">
          <span
            className="size-2.5 rounded-sm"
            style={r.outline ? { border: `2px solid ${r.color}` } : { background: r.color }}
          />
          <span>{r.name}</span>
          <span className="num ml-auto pl-3 text-muted-foreground">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

export function SensorDonut({ view }: { view: QueueView }) {
  const s = view.summary;
  if (!s) return null;
  const data = SENSORS.map((x) => ({
    name: x.label,
    value: s.alerts_by_sensor[x.key],
    color: x.color,
  }));
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  const top = [...data].sort((a, b) => b.value - a.value)[0]!;
  return (
    <figure className="card m-0 px-5 py-4">
      <figcaption className="text-[13px] font-semibold">Alerts by sensor</figcaption>
      <div className="mt-0.5 text-xs text-muted-foreground">{n(s.alerts)} after cleanup</div>
      <div className="mt-3 flex flex-wrap items-center gap-5">
        <Donut
          data={data}
          center={`${Math.round((top.value / total) * 100)}%`}
          sub={top.name}
          label={`Alerts by sensor: ${data.map((d) => `${d.name} ${n(d.value)}`).join(", ")}`}
        />
        <Legend rows={data.map((d) => ({ name: d.name, value: n(d.value), color: d.color }))} />
      </div>
    </figure>
  );
}

export function OutcomeDonut({ view }: { view: QueueView }) {
  const c = view.counts;
  const data = [
    { name: "Confirmed", value: c.confirmed, color: "var(--brand-accent)" },
    { name: "Below threshold", value: c.below, color: "#4a5372" },
    ...(c.unscored ? [{ name: "No model score", value: c.unscored, color: "#2f3856" }] : []),
  ];
  return (
    <figure className="card m-0 px-5 py-4">
      <figcaption className="text-[13px] font-semibold">Incident outcome</figcaption>
      <div className="mt-0.5 text-xs text-muted-foreground">
        {n(c.incidents)} incidents scored by the window model
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-5">
        <Donut
          data={data}
          center={`${c.confirmed} / ${c.incidents}`}
          sub="confirmed"
          label={`Incident outcome: ${data.map((d) => `${d.value} ${d.name.toLowerCase()}`).join(", ")}`}
        />
        <Legend rows={data.map((d) => ({ name: d.name, value: n(d.value), color: d.color }))} />
      </div>
    </figure>
  );
}

// ------------------------------------------------------------------ alerts per host (log scale)

export function HostBars({ view }: { view: QueueView }) {
  const rows = view.hostAlerts.slice(0, 6);
  if (!rows.length) return null;
  const total = view.hostAlerts.reduce((s, r) => s + r.alerts, 0) || 1;
  const maxLog = Math.log10((rows[0]?.alerts ?? 1) + 1) || 1;
  const topShare = Math.round(((rows[0]?.alerts ?? 0) / total) * 100);
  return (
    <figure className="card m-0 px-5 py-4">
      <figcaption className="text-[13px] font-semibold">Alerts per host</figcaption>
      <div className="mt-0.5 text-xs text-muted-foreground">
        alerts inside incidents · top {rows.length} · log scale · the top host took {topShare}%
      </div>
      <div className="mt-3 flex flex-col gap-2 text-xs">
        {rows.map((r) => (
          <div
            key={r.entity}
            title={`${r.entity} · ${n(r.alerts)} alerts in ${r.incidents} incident${r.incidents === 1 ? "" : "s"}`}
            className="grid grid-cols-[116px_minmax(0,1fr)_64px] items-center gap-2.5"
          >
            <span className="num truncate">{r.entity}</span>
            <div className="h-2.5">
              <div
                className="h-2.5 rounded-r"
                style={{
                  width: `${Math.max(4, (Math.log10(r.alerts + 1) / maxLog) * 100)}%`,
                  background: "var(--sensor-wazuh)",
                }}
              />
            </div>
            <span className="num text-right text-muted-foreground">{n(r.alerts)}</span>
          </div>
        ))}
      </div>
    </figure>
  );
}

// ------------------------------------------------------------------ ablation

export function AblationPanel() {
  const his = ABLATION_ARMS.find((a) => a.key === "his")!;
  const both = ABLATION_ARMS.find((a) => a.key === "his+st")!;
  const panels = [
    {
      title: "Mean average precision · loud attack stages",
      values: [his.meanAP, both.meanAP],
      max: 1,
      fmt: (v: number) => v.toFixed(2),
    },
    {
      title: "Recall at a 1% alert budget",
      values: [his.recallAt1pct, both.recallAt1pct],
      max: 1,
      fmt: (v: number) => v.toFixed(2),
    },
  ];
  const colors = ["var(--sensor-wazuh)", "var(--sensor-suricata)"];
  const labels = [his.label, both.label];
  return (
    <figure className="card col-span-full m-0 px-5 py-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <figcaption className="text-[13px] font-semibold">
          Adding our per-host statistics to the model
        </figcaption>
        <div className="flex flex-wrap gap-3.5 text-xs text-secondary-foreground">
          {labels.map((l, i) => (
            <span key={l} className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-sm" style={{ background: colors[i] }} />
              {l}
            </span>
          ))}
        </div>
      </div>
      <div className="mt-0.5 text-xs text-muted-foreground">{ABLATION_NOTE}</div>
      <div className="mt-4 grid gap-6 sm:grid-cols-2">
        {panels.map((p) => (
          <div key={p.title}>
            <div className="mb-2.5 text-xs text-secondary-foreground">{p.title}</div>
            <div className="flex flex-col gap-1.5">
              {p.values.map((v, i) => (
                <div
                  key={i}
                  title={`${labels[i]} · ${p.fmt(v)}`}
                  className="flex items-center gap-2.5"
                >
                  <div
                    className="h-3.5 rounded-r"
                    style={{ width: `${Math.max(3, (v / p.max) * 100)}%`, background: colors[i] }}
                  />
                  <span className="num text-xs">{p.fmt(v)}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 text-[11px] text-muted-foreground">Source: {ABLATION_SOURCE}</div>
    </figure>
  );
}

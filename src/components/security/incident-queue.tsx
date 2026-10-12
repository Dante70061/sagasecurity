import {
  Activity,
  Crosshair,
  ListOrdered,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { IncidentGroup, QueueView, RankedIncident } from "@/data/incidents";

const GROUPS: { id: IncidentGroup; label: string; hint: string }[] = [
  { id: "confirmed", label: "Confirmed by model", hint: "p_attack ≥ 0.5, ordered by peak z" },
  { id: "below", label: "Below threshold", hint: "p_attack < 0.5, ordered by peak z" },
  { id: "unscored", label: "Model score unavailable", hint: "ranked by peak z only" },
];

export function utcLabel(iso: string): string {
  return iso
    .replace("T", " ")
    .replace(/:\d\d(\.\d+)?\+00:00$/, "")
    .slice(5);
}

export function spanMinutes(start: string, end: string): number {
  return Math.round((Date.parse(end) - Date.parse(start)) / 60_000);
}

export function pLabel(incident: RankedIncident): string {
  const p = incident.model?.p_max;
  return p == null ? "n/a" : p.toFixed(3);
}

export function IncidentFunnel({ view }: { view: QueueView }) {
  const tiles = [
    {
      label: view.scenario ? "Alerts in scenario" : "Alerts analysed",
      value: view.summary ? view.summary.alerts.toLocaleString("en-US") : "—",
      icon: Activity,
      hint: view.summary
        ? `${view.summary.hosts} hosts · ${view.summary.minutes.toLocaleString("en-US")} minutes`
        : "pick a scenario",
    },
    {
      label: "Incidents",
      value: view.counts.incidents.toLocaleString("en-US"),
      icon: Radar,
      hint: "anomalous windows merged by host or source IP",
    },
    {
      label: "Confirmed by model",
      value: view.counts.confirmed.toLocaleString("en-US"),
      icon: ShieldAlert,
      hint: "p_attack ≥ 0.5",
    },
  ];
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {tiles.map(({ label, value, icon: Icon, hint }) => (
        <article className="panel metric-card" key={label}>
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">{label}</span>
            <Icon className="size-4 text-muted-foreground" />
          </div>
          <div className="mt-2">
            <span className="metric-number">{value}</span>
          </div>
          <p className="mt-1 text-[10px] text-muted-foreground">{hint}</p>
        </article>
      ))}
    </div>
  );
}

function Picker({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
      {label}
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-7 rounded-md border border-border bg-card px-2 text-[11px] text-secondary-foreground focus:outline-none focus:ring-1 focus:ring-primary"
      >
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

export function IncidentQueue({
  view,
  selectedId,
  loading,
  onSelect,
  onRunChange,
  onScenarioChange,
}: {
  view: QueueView;
  selectedId: string | null;
  loading: boolean;
  onSelect: (id: string) => void;
  onRunChange: (run: string) => void;
  onScenarioChange: (scenario: string) => void;
}) {
  return (
    <section className="panel" aria-busy={loading}>
      <div className="panel-heading flex-wrap">
        <div className="flex items-center gap-2.5">
          <ListOrdered className="size-4 text-primary" />
          <h2>Incident queue</h2>
          <span className="flex h-5 min-w-5 items-center justify-center rounded bg-muted px-1 font-mono text-[10px] text-muted-foreground">
            {view.counts.incidents}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Picker label="Run" value={view.run} options={view.runs} onChange={onRunChange} />
          {view.scenarios.length > 1 && (
            <Picker
              label="Scenario"
              value={view.scenario ?? "all"}
              options={["all", ...view.scenarios]}
              onChange={onScenarioChange}
            />
          )}
        </div>
      </div>
      <div className={`max-h-[34rem] overflow-y-auto ${loading ? "opacity-60" : ""}`}>
        {GROUPS.map((group) => {
          const rows = view.incidents.filter((i) => i.group === group.id);
          if (!rows.length) return null;
          return (
            <div key={group.id}>
              <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-card/95 px-5 py-2 backdrop-blur">
                <span className="kicker flex items-center gap-2">
                  {group.id === "confirmed" ? (
                    <ShieldAlert className="size-3 text-primary" />
                  ) : (
                    <ShieldCheck className="size-3" />
                  )}
                  {group.label}
                  <span className="font-mono normal-case tracking-normal">({rows.length})</span>
                </span>
                <span className="text-[10px] text-muted-foreground">{group.hint}</span>
              </div>
              {rows.map((incident) => (
                <IncidentRow
                  key={`${incident.run}:${incident.incident_id}`}
                  incident={incident}
                  selected={incident.incident_id === selectedId}
                  onSelect={onSelect}
                />
              ))}
            </div>
          );
        })}
        {!view.incidents.length && (
          <div className="findings-empty">
            <div className="findings-icon">
              <Radar className="size-7" strokeWidth={1.25} />
            </div>
            <div>
              <h3 className="text-sm font-medium">No incidents in this selection</h3>
              <p className="max-w-lg text-xs leading-6 text-muted-foreground">
                Pick another run or scenario.
              </p>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function IncidentRow({
  incident,
  selected,
  onSelect,
}: {
  incident: RankedIncident;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const Icon = incident.kind === "actor" ? Crosshair : Server;
  const reason = incident.reasons[0]?.text ?? "no reason recorded";
  return (
    <button
      type="button"
      aria-pressed={selected}
      onClick={() => onSelect(incident.incident_id)}
      className={`block w-full border-b border-border px-5 py-3 text-left transition-colors hover:bg-accent/40 ${selected ? "bg-accent/60" : ""}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="flex items-center gap-2 text-xs font-medium">
          <span className="font-mono text-[10px] text-muted-foreground">#{incident.rank}</span>
          <span className="font-mono">{incident.incident_id}</span>
          <Icon className="size-3 text-muted-foreground" />
          <span>{incident.entity}</span>
          {incident.scenario && (
            <span className="rounded border border-border px-1 font-mono text-[9px] text-muted-foreground">
              {incident.scenario}
            </span>
          )}
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          p {pLabel(incident)} · z {incident.peak_z}
        </span>
      </div>
      <p className="mt-1 text-[11px] text-muted-foreground">
        {utcLabel(incident.start)} UTC · {spanMinutes(incident.start, incident.end)} min ·{" "}
        {incident.n_alerts.toLocaleString("en-US")} alerts · {reason}
      </p>
    </button>
  );
}

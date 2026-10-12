import { Crosshair, Link2, Server, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { RankedIncident } from "@/data/incidents";
import { pLabel, spanMinutes, utcLabel } from "./incident-queue";

export function IncidentDetail({
  incident,
  byId,
  onSelect,
}: {
  incident: RankedIncident | null;
  byId: Map<string, RankedIncident>;
  onSelect: (id: string) => void;
}) {
  if (!incident) {
    return (
      <section className="panel flex min-h-64 flex-col items-center justify-center gap-3 p-8 text-center">
        <ShieldAlert className="size-8 text-muted-foreground" />
        <h2 className="text-sm">Select an incident</h2>
        <p className="text-xs text-muted-foreground">The queue on the left is ranked for triage.</p>
      </section>
    );
  }
  const Icon = incident.kind === "actor" ? Crosshair : Server;
  const p = incident.model?.p_max;
  const facts: [string, string][] = [
    ["Kind", incident.kind === "actor" ? "Actor (source IP across hosts)" : "Host"],
    ["Entity", incident.entity],
    ["Scenario", `${incident.scenario} · run ${incident.run}`],
    [
      "Window",
      `${utcLabel(incident.start)} to ${utcLabel(incident.end)} UTC · ${spanMinutes(incident.start, incident.end)} min`,
    ],
    [
      "Model",
      p == null
        ? "score unavailable"
        : `p_attack ${pLabel(incident)} (mean ${incident.model?.p_mean?.toFixed(3) ?? "n/a"})`,
    ],
    [
      "Stats",
      `peak z ${incident.peak_z} · ${incident.n_windows} flagged minutes · ${incident.n_alerts.toLocaleString("en-US")} alerts`,
    ],
    ["Tools", incident.tools.join(", ") || "none"],
  ];
  return (
    <section
      className="panel focus-section"
      id="incident"
      aria-label={`Incident ${incident.incident_id}`}
    >
      <div className="panel-heading">
        <div className="flex items-center gap-2.5">
          <Icon className="size-4 text-primary" />
          <h2 className="font-mono">{incident.incident_id}</h2>
          <span
            className={`rounded border px-1.5 py-0.5 font-mono text-[9px] ${
              incident.group === "confirmed"
                ? "border-primary/25 bg-primary/10 text-primary"
                : "border-border bg-muted text-muted-foreground"
            }`}
          >
            {incident.group === "confirmed"
              ? "CONFIRMED BY MODEL"
              : incident.group === "below"
                ? "BELOW THRESHOLD"
                : "MODEL SCORE UNAVAILABLE"}
          </span>
        </div>
        <span className="font-mono text-[10px] text-muted-foreground">rank #{incident.rank}</span>
      </div>
      <div className="max-h-[34rem] space-y-5 overflow-y-auto px-5 py-4 text-xs">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
          {facts.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="min-w-0 break-words">{v}</dd>
            </div>
          ))}
        </dl>

        <div>
          <span className="kicker">Why it was flagged</span>
          <ul className="mt-2 space-y-1">
            {incident.reasons.map((r) => (
              <li key={r.feature} className="flex items-baseline justify-between gap-3">
                <span>{r.text}</span>
                <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                  {r.feature} · z {r.z}
                </span>
              </li>
            ))}
            {!incident.reasons.length && (
              <li className="text-muted-foreground">no reason recorded</li>
            )}
          </ul>
        </div>

        {incident.kind === "actor" && incident.targets?.length ? (
          <div>
            <span className="kicker">Targets touched</span>
            <p className="mt-2 font-mono text-[11px]">{incident.targets.join(", ")}</p>
          </div>
        ) : null}

        <div>
          <span className="kicker">Top rules</span>
          <ul className="mt-2 space-y-1">
            {incident.top_rules.map((r) => (
              <li
                key={`${r.tool}:${r.detector}`}
                className="flex items-baseline justify-between gap-3"
              >
                <span className="min-w-0 break-words">{r.detector}</span>
                <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                  {r.tool} · {r.count.toLocaleString("en-US")}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <span className="kicker">Sample alerts</span>
          <ul className="mt-2 space-y-2">
            {incident.sample_alerts.slice(0, 5).map((s, n) => (
              <li key={n} className="rounded-md border border-border bg-background/60 p-2">
                <p className="text-[10px] text-muted-foreground">
                  {utcLabel(s.ts)} UTC · {s.tool} · level {s.level}
                  {s.src_ip ? ` · src ${s.src_ip}` : ""}
                  {s.dst_ip ? ` · dst ${s.dst_ip}` : ""}
                </p>
                <p className="mt-1 text-[11px]">{s.detector}</p>
                {s.raw && (
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[10px] text-secondary-foreground">
                    {s.raw}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <span className="kicker">Related incidents</span>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {incident.related.map((id) => {
              const other = byId.get(id);
              return (
                <Button
                  key={id}
                  size="sm"
                  variant="outline"
                  className="h-7 gap-1 px-2 font-mono text-[10px]"
                  disabled={!other}
                  title={other ? `${other.entity} · p ${pLabel(other)}` : "not in this selection"}
                  onClick={() => onSelect(id)}
                >
                  <Link2 className="size-3" />
                  {id}
                  {other && (
                    <span className="text-muted-foreground">
                      {other.kind === "actor" ? "actor" : other.entity}
                    </span>
                  )}
                </Button>
              );
            })}
            {!incident.related.length && (
              <span className="text-muted-foreground">none in the same time range</span>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

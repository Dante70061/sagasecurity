// Left column of the breakdown page: every incident of the run as a link, confirmed first, the
// below-threshold group collapsed by default. Switching incidents never leaves the page.

import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { QueueView, RankedIncident } from "@/data/incidents";
import { shortLabel } from "@/data/triage";
import { decisionLabel, type Decision } from "@/lib/triage-storage";

function Item({
  incident,
  run,
  active,
  decision,
  dim,
}: {
  incident: RankedIncident;
  run: string;
  active: boolean;
  decision: Decision | undefined;
  dim: boolean;
}) {
  const p = incident.model?.p_max;
  return (
    <Link
      to="/incident/$id"
      params={{ id: incident.incident_id }}
      search={{ run }}
      className={`nav-item ${dim ? "text-secondary-foreground" : ""}`}
      aria-current={active ? "page" : undefined}
    >
      <span className="flex w-full justify-between gap-2">
        <span className="num text-[13px] font-medium">{incident.incident_id}</span>
        <span className="num text-xs text-secondary-foreground">
          {p == null ? "no score" : `p ${p.toFixed(2)}`}
        </span>
      </span>
      <span className="text-xs text-secondary-foreground">{shortLabel(incident)}</span>
      <span className="flex w-full justify-between gap-2">
        <span className="num text-[11px] text-muted-foreground">{incident.entity}</span>
        {decision && (
          <span className="text-[11px]" style={{ color: "var(--brand-accent)" }}>
            {decisionLabel(decision)}
          </span>
        )}
      </span>
    </Link>
  );
}

export function IncidentNav({
  view,
  activeId,
  decisions,
}: {
  view: QueueView;
  activeId: string;
  decisions: Map<string, Decision>;
}) {
  const confirmed = view.incidents.filter((i) => i.group === "confirmed");
  const below = view.incidents.filter((i) => i.group !== "confirmed");
  const activeBelow = below.some((i) => i.incident_id === activeId);
  const [open, setOpen] = useState(activeBelow);
  const showBelow = open || activeBelow;
  return (
    <nav aria-label="Incidents" className="card investigate-nav overflow-hidden">
      <div className="band band-confirmed" style={{ borderTop: 0 }}>
        Confirmed by model · {confirmed.length}
      </div>
      <div className="flex flex-col">
        {confirmed.map((i) => (
          <Item
            key={i.incident_id}
            incident={i}
            run={view.run}
            active={i.incident_id === activeId}
            decision={decisions.get(i.incident_id)}
            dim={false}
          />
        ))}
      </div>
      {below.length > 0 && (
        <>
          <div className="band" style={{ background: "#141a2c" }}>
            <span className="font-semibold text-secondary-foreground">
              Below threshold · {below.length}
            </span>
          </div>
          {showBelow ? (
            <div className="flex max-h-[28rem] flex-col overflow-y-auto">
              {below.map((i) => (
                <Item
                  key={i.incident_id}
                  incident={i}
                  run={view.run}
                  active={i.incident_id === activeId}
                  decision={decisions.get(i.incident_id)}
                  dim
                />
              ))}
            </div>
          ) : null}
          {!activeBelow && (
            <div className="px-4 py-3">
              <button
                type="button"
                className="link-btn"
                aria-expanded={showBelow}
                onClick={() => setOpen((v) => !v)}
              >
                {showBelow ? "Hide below threshold" : `Show ${below.length} below threshold`}
              </button>
            </div>
          )}
        </>
      )}
    </nav>
  );
}

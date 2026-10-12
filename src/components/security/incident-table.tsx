// Incident queue as a table. Each row is a link to the breakdown page; the whole row is clickable and
// the incident id carries keyboard focus. Grouped: confirmed by model first, then below threshold,
// then unscored; peak z descending inside each group (ranking is done server-side).

import { Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import type { QueueView, RankedIncident } from "@/data/incidents";
import { clockUtc, shortLabel } from "@/data/triage";

const n = (v: number) => v.toLocaleString("en-US");

function PBar({ incident }: { incident: RankedIncident }) {
  const p = incident.model?.p_max;
  if (p == null)
    return <span className="text-[11px] text-muted-foreground">model score unavailable</span>;
  const confirmed = incident.group === "confirmed";
  return (
    <div className="flex items-center gap-2">
      <div className="bar-track w-14">
        <div
          className="bar-fill"
          style={{
            width: `${Math.round(p * 100)}%`,
            background: confirmed ? "var(--brand-accent)" : "#7c86a3",
          }}
        />
      </div>
      <span className="num">{p.toFixed(2)}</span>
    </div>
  );
}

function Row({ incident, run, dim }: { incident: RankedIncident; run: string; dim: boolean }) {
  const navigate = useNavigate();
  const open = () =>
    void navigate({ to: "/incident/$id", params: { id: incident.incident_id }, search: { run } });
  const muted = dim ? "text-secondary-foreground" : "";
  return (
    <tr className={`q-row ${muted}`} onClick={open}>
      <td className="num text-muted-foreground">{dim ? "·" : incident.rank}</td>
      <td>
        <Link
          to="/incident/$id"
          params={{ id: incident.incident_id }}
          search={{ run }}
          className="num font-medium text-foreground no-underline hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {incident.incident_id}
        </Link>
        <div className="mt-0.5 text-[11px] text-muted-foreground">{shortLabel(incident)}</div>
      </td>
      <td className="num">{incident.entity}</td>
      <td className="num whitespace-nowrap">{clockUtc(incident.start)}</td>
      <td>
        <PBar incident={incident} />
      </td>
      <td className="num">{incident.peak_z}</td>
      <td className="num">{n(incident.n_alerts)}</td>
    </tr>
  );
}

export function IncidentTable({ view }: { view: QueueView }) {
  const confirmed = view.incidents.filter((i) => i.group === "confirmed");
  const below = view.incidents.filter((i) => i.group !== "confirmed");
  const [showAll, setShowAll] = useState(false);
  const shownBelow = showAll ? below : below.slice(0, 3);
  const first = view.incidents[0];
  return (
    <section aria-labelledby="queue-title" className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-5 pb-3.5 pt-4">
        <h2 id="queue-title" className="section-title">
          Incident queue{" "}
          <span className="num ml-1.5 text-xs font-normal text-muted-foreground">
            {view.counts.incidents}
          </span>
        </h2>
        <span className="text-xs text-muted-foreground">
          model decides the group · statistics order within it
          {first && (
            <>
              {" · "}
              <Link
                to="/incident/$id"
                params={{ id: first.incident_id }}
                search={{ run: view.run }}
                className="font-semibold no-underline"
                style={{ color: "var(--brand-accent)" }}
              >
                Investigate incidents →
              </Link>
            </>
          )}
        </span>
      </div>
      <div className="band">
        <span className="band-confirmed">Confirmed by model · {confirmed.length}</span>
        <span className="text-muted-foreground">p_attack ≥ 0.5</span>
      </div>
      <div className="overflow-x-auto">
        <table className="q-table">
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Incident</th>
              <th scope="col">Entity</th>
              <th scope="col">Seen (UTC)</th>
              <th scope="col">p_attack</th>
              <th scope="col">Peak z</th>
              <th scope="col">Alerts</th>
            </tr>
          </thead>
          <tbody>
            {confirmed.map((i) => (
              <Row key={i.incident_id} incident={i} run={view.run} dim={false} />
            ))}
            {!confirmed.length && (
              <tr>
                <td colSpan={7} className="text-muted-foreground">
                  No confirmed incidents in this selection.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {below.length > 0 && (
        <>
          <div className="band" style={{ background: "#141a2c" }}>
            <span className="font-semibold text-secondary-foreground">
              Below threshold · {below.length}
            </span>
            <span className="text-muted-foreground">{view.belowNote ?? "p_attack < 0.5"}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="q-table">
              <tbody>
                {shownBelow.map((i) => (
                  <Row key={i.incident_id} incident={i} run={view.run} dim />
                ))}
              </tbody>
            </table>
          </div>
          {below.length > 3 && (
            <div className="px-5 pb-4 pt-3">
              <button
                type="button"
                className="link-btn"
                aria-expanded={showAll}
                onClick={() => setShowAll((v) => !v)}
              >
                {showAll ? "Show fewer" : `Show all ${below.length} below threshold`}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}

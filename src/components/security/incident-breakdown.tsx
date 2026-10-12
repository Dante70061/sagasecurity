// Full breakdown of one incident (design/Investigate.dc.html). Text blocks are deterministic
// templates from src/data/triage.ts and are labelled as recommendations. Checklist, decision and
// notes persist per incident in localStorage and are read only after hydration.

import { Link } from "@tanstack/react-router";
import { MessageSquareText } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { IncidentPageView, RankedIncident } from "@/data/incidents";
import { clockUtc, minutesBetween, narrative, riskLevel } from "@/data/triage";
import {
  DECISIONS,
  EMPTY_STATE,
  readState,
  writeState,
  type Decision,
  type TriageState,
} from "@/lib/triage-storage";
import { Highlight } from "./highlight";
import { RiskChip } from "./risk-chip";

const n = (v: number) => v.toLocaleString("en-US");

function Reco() {
  return <span className="reco">Recommendation · written from the incident's features</span>;
}

export function IncidentBreakdown({
  view,
  onStateChange,
}: {
  view: IncidentPageView;
  onStateChange?: (id: string, state: TriageState) => void;
}) {
  const { incident, queue } = view;
  const byId = useMemo(() => new Map(queue.incidents.map((i) => [i.incident_id, i])), [queue]);
  const story = useMemo(() => narrative(incident, byId), [incident, byId]);
  const risk = riskLevel(incident);
  const p = incident.model?.p_max;

  const [state, setState] = useState<TriageState>(EMPTY_STATE);
  const [saved, setSaved] = useState(true);
  useEffect(() => {
    setState(readState(queue.run, incident.incident_id));
    setSaved(true);
  }, [queue.run, incident.incident_id]);
  const update = (next: TriageState) => {
    setState(next);
    setSaved(writeState(queue.run, incident.incident_id, next));
    onStateChange?.(incident.incident_id, next);
  };
  const toggleStep = (k: number) => {
    const checks = story.steps.map((_, i) => (i === k ? !state.checks[i] : !!state.checks[i]));
    update({ ...state, checks });
  };
  const pickDecision = (d: Decision) =>
    update({ ...state, decision: state.decision === d ? null : d });
  const done = story.steps.filter((_, i) => state.checks[i]).length;
  const pct = story.steps.length ? Math.round((done / story.steps.length) * 100) : 0;
  const maxZ = Math.max(50, ...incident.reasons.map((r) => r.z));
  const related = incident.related
    .map((id) => byId.get(id))
    .filter((r): r is RankedIncident => !!r);

  return (
    <main aria-labelledby="incident-title" className="investigate-main">
      <section className="card px-6 py-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 id="incident-title" className="num m-0 text-[22px] font-medium">
            {incident.incident_id}
          </h1>
          <RiskChip level={risk} />
          <span className="text-xs text-muted-foreground">
            {incident.group === "confirmed"
              ? "Confirmed by model"
              : incident.group === "below"
                ? "Below threshold"
                : "Model score unavailable"}{" "}
            · rank {incident.rank} of {queue.counts.incidents}
          </span>
        </div>
        <p className="mb-0 mt-3 text-xl font-medium leading-snug">{story.headline}</p>
        <div className="mt-4 grid gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
          {[
            [
              "When (UTC)",
              `${clockUtc(incident.start)} → ${clockUtc(incident.end).slice(6)} · ${minutesBetween(incident.start, incident.end)} min`,
            ],
            [incident.kind === "actor" ? "Source IP" : "Host", incident.entity],
            ["Model · p_attack", p == null ? "unavailable" : p.toFixed(3)],
            ["Alerts · peak z", `${n(incident.n_alerts)} · ${incident.peak_z}`],
          ].map(([k, v]) => (
            <div key={k} className="subcard px-3.5 py-3">
              <div className="text-[11px] text-muted-foreground">{k}</div>
              <div className="num mt-1 text-[13px]">{v}</div>
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Link to="/" search={{ ask: incident.incident_id }} hash="assistant" className="chip-btn">
            <MessageSquareText className="size-3.5" aria-hidden="true" />
            Ask Saga about this incident
          </Link>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section aria-labelledby="what-title" className="card px-6 py-5">
          <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="what-title" className="m-0 text-sm font-semibold">
              What happened
            </h2>
            <Reco />
          </div>
          <p className="m-0 text-sm leading-relaxed text-secondary-foreground">{story.summary}</p>
        </section>
        <section aria-labelledby="why-title" className="card px-6 py-5">
          <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="why-title" className="m-0 text-sm font-semibold">
              Why it matters
            </h2>
            <Reco />
          </div>
          <ul className="m-0 flex flex-col gap-2 pl-4 text-sm leading-relaxed text-secondary-foreground">
            {story.risks.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          {story.blind && (
            <div className="callout">
              <span className="font-semibold text-foreground">Not visible: </span>
              {story.blind}
            </div>
          )}
        </section>
      </div>

      <section aria-labelledby="steps-title" className="card px-6 py-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="steps-title" className="m-0 text-sm font-semibold">
            Triage steps
          </h2>
          <span className="flex items-center gap-3">
            <Reco />
            <span className="num text-xs text-muted-foreground">
              {done} of {story.steps.length} done
            </span>
          </span>
        </div>
        <div
          className="bar-track mb-1.5 mt-3 h-1"
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Triage progress"
        >
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="flex flex-col">
          {story.steps.map((text, k) => (
            <label key={text} className="check-row">
              <input type="checkbox" checked={!!state.checks[k]} onChange={() => toggleStep(k)} />
              <span>{text}</span>
            </label>
          ))}
        </div>
      </section>

      <section aria-labelledby="evidence-title" className="card flex flex-col gap-4 px-6 py-5">
        <h2 id="evidence-title" className="m-0 text-sm font-semibold">
          Evidence
        </h2>
        <div>
          <h3 className="sub-title">Why it was flagged</h3>
          <div className="flex flex-col gap-2.5">
            {incident.reasons.map((r) => (
              <div
                key={r.feature}
                className="grid grid-cols-[minmax(0,1fr)_120px_56px] items-center gap-3 text-[13px]"
              >
                <span>{r.text}</span>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${Math.min(100, Math.round((r.z / maxZ) * 100))}%` }}
                  />
                </div>
                <span className="num text-right text-muted-foreground">z {r.z}</span>
              </div>
            ))}
            {!incident.reasons.length && (
              <span className="text-xs text-muted-foreground">no reason recorded</span>
            )}
          </div>
        </div>
        <div>
          <h3 className="sub-title">Key alerts</h3>
          <div className="flex flex-col gap-2">
            {incident.sample_alerts.slice(0, 4).map((s, i) => (
              <div key={i} className="log-box">
                <div className="num text-[11px] text-muted-foreground">
                  {clockUtc(s.ts)} UTC · {s.tool} · level {s.level}
                  {s.src_ip ? ` · src ${s.src_ip}` : ""}
                  {s.dst_ip ? ` · dst ${s.dst_ip}` : ""}
                </div>
                <div className="mt-1 text-xs">{s.detector}</div>
                {s.raw && (
                  <div className="num mt-1 break-all text-xs leading-relaxed">
                    <Highlight text={s.raw} />
                  </div>
                )}
              </div>
            ))}
            {!incident.sample_alerts.length && (
              <span className="text-xs text-muted-foreground">no sample alerts attached</span>
            )}
          </div>
        </div>
        {incident.top_rules.length > 0 && (
          <div>
            <h3 className="sub-title">Top rules</h3>
            <div className="flex flex-col gap-2 text-[13px]">
              {incident.top_rules.map((r) => (
                <div key={`${r.tool}:${r.detector}`} className="flex justify-between gap-3">
                  <span className="min-w-0 break-words">
                    {r.detector} <span className="text-muted-foreground">· {r.tool}</span>
                  </span>
                  <span className="num shrink-0 text-muted-foreground">{n(r.count)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {incident.kind === "actor" && incident.targets?.length ? (
          <div>
            <h3 className="sub-title">Targets touched</h3>
            <p className="num m-0 text-xs">{incident.targets.join(", ")}</p>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="related-title" className="card px-6 py-5">
        <h2 id="related-title" className="m-0 mb-3 text-sm font-semibold">
          Related incidents
        </h2>
        <div className="flex flex-wrap gap-2">
          {related.map((r) => (
            <Link
              key={r.incident_id}
              to="/incident/$id"
              params={{ id: r.incident_id }}
              search={{ run: queue.run }}
              className="chip-btn"
            >
              <span className="num">{r.incident_id}</span>
              <span className="text-muted-foreground">· {narrative(r, byId).label}</span>
            </Link>
          ))}
          {!related.length && (
            <span className="text-xs text-muted-foreground">none in the same time range</span>
          )}
        </div>
      </section>

      <section
        aria-labelledby="decision-title"
        className="card px-6 py-5"
        style={{ borderColor: "var(--brand-accent)" }}
      >
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="decision-title" className="m-0 text-sm font-semibold">
            Your decision
          </h2>
          {!saved && (
            <span className="text-[11px] text-warning">
              Browser storage is unavailable; this will not be saved.
            </span>
          )}
        </div>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Decision">
          {DECISIONS.map((d) => (
            <button
              key={d.key}
              type="button"
              className="decision-btn"
              aria-pressed={state.decision === d.key}
              onClick={() => pickDecision(d.key)}
            >
              {d.label}
            </button>
          ))}
        </div>
        <label htmlFor="analyst-notes" className="mb-1.5 mt-4 block text-xs text-muted-foreground">
          Analyst notes
        </label>
        <textarea
          id="analyst-notes"
          rows={3}
          value={state.notes}
          onChange={(e) => update({ ...state, notes: e.target.value })}
          placeholder="What you checked, who you contacted, why you decided…"
          className="w-full resize-y rounded-[10px] border border-[#2a3352] bg-background px-3.5 py-3 text-sm leading-normal text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
        />
      </section>
    </main>
  );
}

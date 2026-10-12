import { createServerFn } from "@tanstack/react-start";

export type IncidentReason = { feature: string; z: number; text: string };
export type IncidentRule = { tool: string; detector: string; count: number };
export type SampleAlert = {
  ts: string;
  tool: string;
  detector: string;
  level: number;
  src_ip: string | null;
  dst_ip: string | null;
  raw: string | null;
};
export type IncidentModel = {
  score_col: string;
  n_minutes: number;
  p_max: number | null;
  p_mean: number | null;
  peak_minute_utc: string | null;
};
export type Incident = {
  run: string;
  incident_id: string;
  kind: "host" | "actor";
  scenario: string;
  entity: string;
  start: string;
  end: string;
  peak_z: number;
  n_windows: number;
  n_alerts: number;
  tools: string[];
  targets: string[] | null;
  reasons: IncidentReason[];
  top_rules: IncidentRule[];
  sample_alerts: SampleAlert[];
  related: string[];
  model: IncidentModel | null;
};

export type IncidentGroup = "confirmed" | "below" | "unscored";
export type RankedIncident = Incident & { rank: number; group: IncidentGroup };

export type SensorCounts = { wazuh: number; suricata: number; aminer: number };

export type ScenarioSummary = {
  run: string;
  raw_alerts: number | null; // rows in merged.jsonl before dedup and baseline removal
  alerts: number; // after cleanup: what the stats stage analysed
  alerts_by_sensor: SensorCounts;
  minutes: number;
  hosts: number;
  start: string;
  end: string;
};

export type HostAlerts = { entity: string; alerts: number; incidents: number };

/** Everything the breakdown page needs for one incident plus the nav of its run. */
export type IncidentPageView = {
  queue: QueueView;
  incident: RankedIncident;
};

export type IncidentPageResult =
  { ok: true; view: IncidentPageView } | { ok: false; error: string };

export type QueueView = {
  run: string;
  scenario: string | null;
  runs: string[];
  scenarios: string[];
  summary: ScenarioSummary | null;
  counts: { incidents: number; confirmed: number; below: number; unscored: number };
  hostAlerts: HostAlerts[]; // alerts inside host incidents, per entity, descending
  belowNote: string | null; // e.g. "mostly recurring activity on 10.182.193.181"
  incidents: RankedIncident[];
};

export type QueueResult = { ok: true; view: QueueView } | { ok: false; error: string };

export type QueueSelection = { run?: string; scenario?: string };

const NAME = /^[a-z0-9_-]{1,40}$/i;
const INCIDENT_ID = /^INC-\d{4}$/;

export function parseIncidentRef(input: unknown): QueueSelection & { id: string } {
  const sel = parseSelection(input);
  const id = (input as { id?: unknown } | null)?.id;
  if (typeof id !== "string" || !INCIDENT_ID.test(id))
    throw new Error("id must look like INC-0001.");
  return { ...sel, id };
}

export function parseSelection(input: unknown): QueueSelection {
  if (input == null) return {};
  if (typeof input !== "object") throw new Error("Send a run and scenario.");
  const { run, scenario } = input as { run?: unknown; scenario?: unknown };
  const out: QueueSelection = {};
  if (run != null) {
    if (typeof run !== "string" || !NAME.test(run)) throw new Error("run must be a short name.");
    out.run = run;
  }
  if (scenario != null) {
    if (typeof scenario !== "string" || !NAME.test(scenario))
      throw new Error("scenario must be a short name.");
    out.scenario = scenario;
  }
  return out;
}

export const loadIncidentQueue = createServerFn({ method: "GET" })
  .validator((input: unknown) => parseSelection(input))
  .handler(async ({ data }): Promise<QueueResult> => {
    try {
      const { buildQueueView } = await import("./incidents.server");
      return { ok: true, view: await buildQueueView(data.run, data.scenario) };
    } catch (error) {
      console.error(error);
      return { ok: false, error: "The incident list could not be read." };
    }
  });

export const loadIncidentPage = createServerFn({ method: "GET" })
  .validator((input: unknown) => parseIncidentRef(input))
  .handler(async ({ data }): Promise<IncidentPageResult> => {
    try {
      const { buildIncidentPage } = await import("./incidents.server");
      const view = await buildIncidentPage(data.id, data.run, data.scenario);
      return view
        ? { ok: true, view }
        : { ok: false, error: `No incident ${data.id} in this run.` };
    } catch (error) {
      console.error(error);
      return { ok: false, error: "The incident could not be read." };
    }
  });

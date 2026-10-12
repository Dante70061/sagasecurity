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

export type ScenarioSummary = {
  run: string;
  alerts: number;
  minutes: number;
  hosts: number;
  start: string;
  end: string;
};

export type QueueView = {
  run: string;
  scenario: string | null;
  runs: string[];
  scenarios: string[];
  summary: ScenarioSummary | null;
  counts: { incidents: number; confirmed: number; below: number; unscored: number };
  incidents: RankedIncident[];
};

export type QueueResult = { ok: true; view: QueueView } | { ok: false; error: string };

export type QueueSelection = { run?: string; scenario?: string };

const NAME = /^[a-z0-9_-]{1,40}$/i;

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

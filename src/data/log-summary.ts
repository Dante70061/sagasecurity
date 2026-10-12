import { createServerFn } from "@tanstack/react-start";

export type ActivityPoint = { time: string; events: number; baseline: number };

export type PeakHourDetector = { detector: string; count: number; share: number };

export type PeakHour = { label: string; total: number; detectors: PeakHourDetector[] };

export type EventSlice = { name: string; count: number; share: number };

export type LogFinding = {
  id: string;
  source: string;
  detector: string;
  detectorId: string;
  level: number | null;
  severity: "Critical" | "High" | "Medium" | "Low" | null;
  count: number;
  host: string;
  location: string;
  srcIp: string | null;
  lastTs: number;
};

export type LogView = {
  file: string;
  events: number;
  trainingRows: number;
  logFiles: number;
  collectors: string[];
  srcIps: number;
  identities: string[];
  eventChange: string;
  ipChange: string;
  spanLabel: string;
  hours: ActivityPoint[];
  days: ActivityPoint[];
  peakHour: PeakHour;
  distribution: EventSlice[];
  findings: LogFinding[];
};

export type LogSummaryResult = { ok: true; view: LogView } | { ok: false; error: string };

export const loadLogSummary = createServerFn({ method: "GET" }).handler(async (): Promise<LogSummaryResult> => {
  const { readLogSummary } = await import("./log-summary.server");
  try {
    return { ok: true, view: readLogSummary().view };
  } catch {
    return { ok: false, error: "The merged log could not be read." };
  }
});

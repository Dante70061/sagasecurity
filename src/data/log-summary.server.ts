import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { EventSlice, PeakHour } from "./log-summary";

const FILE = "dataset/russellmitchell_merged.jsonl";

const SU_RE = /\bSuccessful su for (\S+) by (\S+)/;
const DOVECOT_USER_RE = /\buser=<([^>]+)>/;
const ACCEPTED_USER_RE = /\bAccepted \S+ for (\S+) from\b/;
const FOR_USER_RE = /\bfor user (\S+)/;
const ACCT_USER_RE = /\bacct="([^"]+)"/;
const RUSER_RE = /\bruser=(\S+)/;
const APACHE_USER_RE = /^(\S+) \S+ (\S+) \[/;
const BLANK_USERS = new Set(["", "-", "?", "none", "null"]);

export type ActivityPoint = { time: string; events: number; baseline: number };

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

type Group = LogFinding & { lastTs: number };

let cache: { view: LogView; prompt: string } | undefined;

function cleanUser(value: string | undefined): string | null {
  if (!value) return null;
  const text = value.trim().replace(/^["'<]+|["'>]+$/g, "");
  if (BLANK_USERS.has(text.toLowerCase()) || text.startsWith("(uid=")) return null;
  return text || null;
}

function usersIn(raw: string): string[] {
  const found: string[] = [];
  const su = SU_RE.exec(raw);
  if (su) {
    for (const group of [su[1], su[2]]) {
      const user = cleanUser(group);
      if (user) found.push(user);
    }
  }
  for (const pattern of [DOVECOT_USER_RE, ACCEPTED_USER_RE, FOR_USER_RE, ACCT_USER_RE, RUSER_RE]) {
    const match = pattern.exec(raw);
    const user = cleanUser(match?.[1]);
    if (user) found.push(user);
  }
  const apache = APACHE_USER_RE.exec(raw);
  const authUser = cleanUser(apache?.[2]);
  if (authUser) found.push(authUser);
  return found;
}

function peelIp(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/.exec(value);
  return match ? match[1] : null;
}

function family(location: string): string {
  const path = location.toLowerCase();
  if (path.includes("suricata")) return "Suricata";
  if (path.includes("/apache2/")) return "Apache";
  if (path.includes("mail") || path.includes("exim")) return "Mail";
  if (path.includes("syslog") || path.includes("/messages") || path.includes("user.log")) return "Syslog";
  if (path.includes("horde")) return "Horde";
  if (path.includes("auth.log") || path.includes("audit")) return "Auth";
  if (path.includes("dnsmasq") || path.includes("openvpn")) return "Dns and VPN";
  return "Other";
}

// Wazuh's own scale: 15 severe, 12–14 high importance, 7–11 below that, 0–6 low relevance.
function severity(level: number | null): LogFinding["severity"] {
  if (level == null) return null;
  if (level >= 15) return "Critical";
  if (level >= 12) return "High";
  if (level >= 7) return "Medium";
  return "Low";
}

function percentChange(current: number, prior: number): string {
  if (prior === 0) return current === 0 ? "0%" : "n/a";
  const value = ((current - prior) / prior) * 100;
  const rounded = value.toFixed(1);
  return value > 0 ? `+${rounded}%` : `${rounded}%`;
}

function hourLabel(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(11, 16);
}

function dayLabel(day: string): string {
  const date = new Date(`${day}T00:00:00Z`);
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
}

function eventDistribution(families: Map<string, number>, total: number): EventSlice[] {
  const ranked = [...families.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const named: { name: string; count: number }[] = [];
  let other = 0;
  for (const [name, count] of ranked) {
    if (name === "Other" || count / total < 0.01) other += count;
    else named.push({ name, count });
  }
  if (other > 0) named.push({ name: "Other", count: other });
  const slices = named.map((row) => ({
    ...row,
    share: total ? Math.round((row.count / total) * 1000) / 10 : 0,
  }));
  const drift = Math.round((100 - slices.reduce((sum, row) => sum + row.share, 0)) * 10) / 10;
  if (slices[0] && drift) slices[0].share = Math.round((slices[0].share + drift) * 10) / 10;
  return slices;
}

function hourSpan(start: number): string {
  const startDate = new Date(start * 1000);
  const endDate = new Date((start + 3600) * 1000);
  const clock = (date: Date) => date.toISOString().slice(11, 16);
  const day = startDate.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
  return `${clock(startDate)}–${clock(endDate)} UTC, ${day}`;
}

function peakHourDetectors(counts: Map<string, number>, total: number, label: string): PeakHour {
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const top = ranked.slice(0, 5);
  const rest = ranked.slice(5).reduce((sum, [, count]) => sum + count, 0);
  const rows = (rest > 0 ? [...top, ["Other", rest] as const] : top).sort(
    (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
  );
  return {
    label,
    total,
    detectors: rows.map(([detector, count]) => ({
      detector,
      count,
      share: total ? Math.round((count / total) * 1000) / 10 : 0,
    })),
  };
}

export function readLogSummary(): { view: LogView; prompt: string } {
  if (cache) return cache;
  const text = readFileSync(join(process.cwd(), FILE), "utf8");
  const identities = new Set<string>();
  const locations = new Set<string>();
  const ips = new Set<string>();
  const lastIps = new Set<string>();
  const priorIps = new Set<string>();
  const collectors = new Set<string>();
  const families = new Map<string, number>();
  const groups = new Map<string, Group>();
  const examples = new Map<string, string>();

  let events = 0;
  let trainingRows = 0;
  let tmin = Number.POSITIVE_INFINITY;
  let tmax = 0;

  const stamps: number[] = [];
  const baselines: boolean[] = [];
  const ipAt: string[] = [];
  const detectorAt: string[] = [];

  for (const line of text.split("\n")) {
    if (!line) continue;
    const row = JSON.parse(line) as {
      ts?: number;
      source?: string;
      host?: string;
      location?: string;
      detector?: string;
      detector_id?: string;
      src_ip?: string;
      dst_ip?: string;
      raw?: string;
      is_baseline?: boolean;
      extras?: { rule_level?: number; training_mode?: boolean };
    };
    const ts = Number(row.ts);
    if (!Number.isFinite(ts)) continue;
    events += 1;
    if (row.extras?.training_mode) trainingRows += 1;
    tmin = Math.min(tmin, ts);
    tmax = Math.max(tmax, ts);
    stamps.push(ts);
    baselines.push(Boolean(row.is_baseline));
    detectorAt.push(row.detector || "(no detector)");

    const source = row.source || "unknown";
    collectors.add(source);
    const location = row.location || "(none)";
    locations.add(location);
    families.set(family(location), (families.get(family(location)) ?? 0) + 1);

    const rowIps = [peelIp(row.src_ip), peelIp(row.dst_ip)].filter((ip): ip is string => ip != null);
    for (const ip of rowIps) ips.add(ip);
    ipAt.push(rowIps[0] ?? "");

    for (const user of usersIn(row.raw ?? "")) identities.add(user);

    const level = typeof row.extras?.rule_level === "number" ? row.extras.rule_level : null;
    const detector = row.detector || "(no detector)";
    const detectorId = String(row.detector_id ?? "");
    const id = `${source}:${detectorId}:${detector}`;
    const current = groups.get(id);
    if (!current || ts >= current.lastTs) {
      groups.set(id, {
        id,
        source,
        detector,
        detectorId,
        level: current?.level ?? level,
        severity: severity(current?.level ?? level),
        count: (current?.count ?? 0) + 1,
        host: row.host || "—",
        location,
        srcIp: peelIp(row.src_ip),
        lastTs: ts,
      });
      if (row.raw) examples.set(id, row.raw.slice(0, 240));
    } else {
      current.count += 1;
    }
  }

  const lastStart = tmax - 86_400;
  const priorStart = tmax - 172_800;
  let lastEvents = 0;
  let priorEvents = 0;
  const hourEvents = new Array<number>(24).fill(0);
  const hourBaseline = new Array<number>(24).fill(0);
  const hourDetectors = Array.from({ length: 24 }, () => new Map<string, number>());
  const dayEvents = new Map<string, number>();
  const dayBaseline = new Map<string, number>();

  for (let i = 0; i < stamps.length; i += 1) {
    const ts = stamps[i];
    const day = new Date(ts * 1000).toISOString().slice(0, 10);
    dayEvents.set(day, (dayEvents.get(day) ?? 0) + 1);
    if (baselines[i]) dayBaseline.set(day, (dayBaseline.get(day) ?? 0) + 1);
    if (ts > lastStart && ts <= tmax) {
      lastEvents += 1;
      const bucket = Math.min(23, Math.floor((ts - lastStart) / 3600));
      hourEvents[bucket] += 1;
      if (baselines[i]) hourBaseline[bucket] += 1;
      const detector = detectorAt[i];
      hourDetectors[bucket].set(detector, (hourDetectors[bucket].get(detector) ?? 0) + 1);
      if (ipAt[i]) lastIps.add(ipAt[i]);
    } else if (ts > priorStart && ts <= lastStart) {
      priorEvents += 1;
      if (ipAt[i]) priorIps.add(ipAt[i]);
    }
  }

  const distribution = eventDistribution(families, events);

  const findings = [...groups.values()].sort((a, b) => (b.level ?? -1) - (a.level ?? -1) || b.count - a.count);

  const hours = hourEvents.map((count, index) => ({
    time: hourLabel(lastStart + index * 3600),
    events: count,
    baseline: hourBaseline[index],
  }));
  const peakIndex = hourEvents.reduce((best, count, index) => (count > hourEvents[best] ? index : best), 0);
  const peakHour = peakHourDetectors(
    hourDetectors[peakIndex],
    hourEvents[peakIndex],
    hourSpan(lastStart + peakIndex * 3600),
  );
  const days = [...dayEvents.keys()].sort().map((day) => ({
    time: dayLabel(day),
    events: dayEvents.get(day) ?? 0,
    baseline: dayBaseline.get(day) ?? 0,
  }));

  const view: LogView = {
    file: FILE,
    events,
    trainingRows,
    logFiles: locations.size,
    collectors: [...collectors].sort(),
    srcIps: ips.size,
    identities: [...identities].sort(),
    eventChange: percentChange(lastEvents, priorEvents),
    ipChange: percentChange(lastIps.size, priorIps.size),
    spanLabel: `${new Date(tmin * 1000).toISOString().slice(0, 16).replace("T", " ")} – ${new Date(tmax * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`,
    hours,
    days,
    peakHour,
    distribution,
    findings,
  };

  const top = findings.filter((finding) => (finding.level ?? 0) >= 8).slice(0, 8);
  const exampleLines = top
    .map((finding) => {
      const raw = examples.get(finding.id) ?? "";
      return `- ${finding.source} ${finding.detector} · level ${finding.level ?? "none"} · ${finding.count} rows · host ${finding.host} · ${finding.location} · src ${finding.srcIp ?? "none"} · raw: ${raw}`;
    })
    .join("\n");
  const prompt = `Counted from ${FILE}. ${events} rows. ${trainingRows} of those are AMiner training_mode rows and are still in the file.
Span ${view.spanLabel}.
Collectors: ${view.collectors.join(", ")}. Log files: ${view.logFiles}.
Unique src/dst IPs: ${view.srcIps}. Last 24h vs the prior 24h in this file: events ${view.eventChange}, IPs ${view.ipChange}.
Identities parsed from raw lines (${view.identities.length}): ${view.identities.join(", ") || "none"}.
Log families: ${distribution.map((item) => `${item.name} ${item.count}`).join(", ")}.
Highest Wazuh rule_level groups:
${exampleLines}`;

  cache = { view, prompt };
  return cache;
}

export function evidencePack(): string {
  return readLogSummary().prompt;
}

// Deterministic triage text for one incident. No model call: everything here is a template chosen by
// the incident's dominant statistical features and filled with values from the incident itself
// (entity, rules, sample alerts, related incidents). Every block produced here is a recommendation,
// not a finding, and the UI labels it that way. Pure functions, unit tested.

import type { Incident, RankedIncident } from "./incidents";

export type RiskLevel = "high" | "medium" | "low";

export type FeatureFamily =
  | "entry_point" // actor incident: a source IP acting across hosts
  | "web_attack" // web-attack rules or a high-severity burst made of web-server rules
  | "privilege" // logins, failed logins, sudo/su, audit
  | "scan" // scan signatures, many targets or ports
  | "first_time" // alert types never or rarely seen
  | "volume" // plain volume or severity burst
  | "other";

export type Narrative = {
  family: FeatureFamily;
  label: string; // short, for table rows and nav items
  headline: string;
  summary: string;
  risks: string[];
  blind: string | null;
  steps: string[];
  routine: boolean; // below threshold: framed as likely routine
};

export const CONFIRMED_THRESHOLD = 0.5;

/** Risk is a recommendation built from the model decision and the statistics.
 *  High:   the model confirmed it (p_attack >= 0.5) and the peak z-score is extreme (>= 12).
 *  Medium: the model confirmed it but the anomaly is modest.
 *  Low:    below threshold or no model score. The statistics alone never raise risk above Low,
 *          because the stats stage flags routine bursts too; the model is what separates them. */
export function riskLevel(incident: Incident): RiskLevel {
  const p = incident.model?.p_max;
  if (p == null || p < CONFIRMED_THRESHOLD) return "low";
  return incident.peak_z >= 12 ? "high" : "medium";
}

export function riskLabel(level: RiskLevel): string {
  return level === "high" ? "High risk" : level === "medium" ? "Medium risk" : "Low risk";
}

/** Feature names sorted by z, strongest first. */
export function dominantFeatures(incident: Incident): string[] {
  return [...incident.reasons].sort((a, b) => b.z - a.z).map((r) => r.feature);
}

const PRIVILEGE = new Set(["priv", "auth_success", "auth_fail", "audit"]);
const SCAN = new Set(["sig_scan", "n_targets", "n_ports"]);
const FIRST_TIME = new Set(["new_rule", "rare_rule", "aminer_novel"]);
const VOLUME = new Set([
  "total",
  "is_wazuh",
  "is_suricata",
  "is_aminer",
  "n_rules",
  "max_level",
  "high_level",
]);
const WEB_RULE = /web|http|apache|wordpress|cms|url|sql/i;

export function featureFamily(incident: Incident): FeatureFamily {
  if (incident.kind === "actor") return "entry_point";
  const feats = dominantFeatures(incident);
  const top = feats[0];
  if (!top) return "other";
  const webRules = incident.top_rules.some((r) => WEB_RULE.test(r.detector));
  if (top === "web_attack" || feats.includes("web_attack")) return "web_attack";
  if (PRIVILEGE.has(top)) return "privilege";
  if (SCAN.has(top)) return "scan";
  if (FIRST_TIME.has(top)) return feats.some((f) => PRIVILEGE.has(f)) ? "privilege" : "first_time";
  if (VOLUME.has(top)) return webRules ? "web_attack" : "volume";
  return "other";
}

// ------------------------------------------------------------------ values pulled from the incident

const SU_RE = /\bSuccessful su for (\S+) by (\S+)/;
const SESSION_RE = /session opened for user (\S+)/;
const ACCEPTED_RE = /\bAccepted \S+ for (\S+) from\b/;
const SUDO_RE = /sudo:\s+([A-Za-z0-9._-]+)\s*:/; // "sudo:  jwilkinson : TTY=…", not "sudo: pam_unix(…)"
const SUDO_TARGET_RE = /\bUSER=(\S+)\b/;
const ACCT_RE = /\bacct="([^"]+)"/;
const PATH_RE =
  /(\/var\/www\/[^\s"']+|\/wp-content\/[^\s"']+|\/[\w.-]+\/[\w./-]+\.(?:php|sh|py|pl))/;
const UA_HINTS =
  /(nmap|wpscan|dirbuster|dirb|sqlmap|nikto|gobuster|masscan|hydra|metasploit|curl|python-requests)/i;
const BLANK = new Set(["", "-", "?", "none", "null", "root"]);

function clean(value: string | undefined): string | null {
  if (!value) return null;
  const text = value.replace(/^["'<(]+|["'>),:]+$/g, "");
  return BLANK.has(text.toLowerCase()) || text.startsWith("(uid=") ? null : text;
}

export type Extracted = {
  users: string[];
  elevatedTo: string[];
  paths: string[];
  tools: string[];
  sources: string[];
};

/** Names, paths, tool user agents and source IPs mentioned in the sample alerts. Only what is literally
 *  there; nothing is inferred. */
export function extract(incident: Incident): Extracted {
  const users = new Set<string>();
  const elevated = new Set<string>();
  const paths = new Set<string>();
  const tools = new Set<string>();
  const sources = new Map<string, number>();
  for (const s of incident.sample_alerts) {
    const raw = s.raw ?? "";
    const su = SU_RE.exec(raw);
    if (su) {
      for (const u of [clean(su[1]), clean(su[2])]) if (u) users.add(u);
      if (su[1]) elevated.add(su[1]);
    }
    for (const re of [SESSION_RE, ACCEPTED_RE, SUDO_RE, ACCT_RE]) {
      const u = clean(re.exec(raw)?.[1]);
      if (u) users.add(u);
    }
    const target = SUDO_TARGET_RE.exec(raw)?.[1];
    if (target) elevated.add(target);
    const path = PATH_RE.exec(raw)?.[1];
    if (path) paths.add(path);
    const ua = UA_HINTS.exec(raw)?.[1];
    if (ua) tools.add(ua.toLowerCase());
    if (s.src_ip) sources.set(s.src_ip, (sources.get(s.src_ip) ?? 0) + 1);
  }
  return {
    users: [...users].slice(0, 4),
    elevatedTo: [...elevated].slice(0, 2),
    paths: [...paths].slice(0, 3),
    tools: [...tools].slice(0, 3),
    sources: [...sources.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([ip]) => ip)
      .slice(0, 3),
  };
}

// ------------------------------------------------------------------ formatting helpers

export function minutesBetween(start: string, end: string): number {
  return Math.round((Date.parse(end) - Date.parse(start)) / 60_000);
}

export function clockUtc(iso: string): string {
  return iso
    .replace("T", " ")
    .replace(/:\d\d(\.\d+)?\+00:00$/, "")
    .slice(5);
}

function n(value: number): string {
  return value.toLocaleString("en-US");
}

function ruleName(detector: string): string {
  return detector.replace(/\.$/, "");
}

function list(items: string[], conj = "and"): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} ${conj} ${items[items.length - 1]}`;
}

const NEIGHBOUR_WINDOW_MIN = 120;

/** Other incidents on the same entity within two hours, from the run's queue. The stats stage only
 *  links incidents that overlap in time, so a follow-on 27 minutes later is not in related[]. */
export function sameEntityNeighbours(
  incident: Incident,
  byId: Map<string, RankedIncident>,
): { id: string; offsetMin: number; incident: RankedIncident }[] {
  const t0 = Date.parse(incident.start);
  return [...byId.values()]
    .filter(
      (r) =>
        r.incident_id !== incident.incident_id &&
        r.run === incident.run &&
        r.entity === incident.entity &&
        r.kind === incident.kind,
    )
    .map((r) => ({
      id: r.incident_id,
      offsetMin: Math.round((Date.parse(r.start) - t0) / 60_000),
      incident: r,
    }))
    .filter((r) => Math.abs(r.offsetMin) <= NEIGHBOUR_WINDOW_MIN)
    .sort((a, b) => a.offsetMin - b.offsetMin);
}

/** Related incidents in time order with their offset from this one, same run only. */
export function relatedTimeline(
  incident: Incident,
  byId: Map<string, RankedIncident>,
): { id: string; offsetMin: number; sameEntity: boolean; incident: RankedIncident }[] {
  const t0 = Date.parse(incident.start);
  return incident.related
    .map((id) => byId.get(id))
    .filter((r): r is RankedIncident => !!r)
    .map((r) => ({
      id: r.incident_id,
      offsetMin: Math.round((Date.parse(r.start) - t0) / 60_000),
      sameEntity: r.entity === incident.entity,
      incident: r,
    }))
    .sort((a, b) => a.offsetMin - b.offsetMin);
}

// ------------------------------------------------------------------ templates

export function shortLabel(incident: Incident): string {
  const fam = featureFamily(incident);
  const p = incident.model?.p_max;
  const routine = p == null || p < CONFIRMED_THRESHOLD;
  switch (fam) {
    case "entry_point":
      return routine ? "source IP · routine traffic" : "source IP · attack entry point";
    case "web_attack":
      return routine ? "host · web noise" : "host · web attack";
    case "privilege":
      return routine ? "host · routine login" : "host · login, privilege use";
    case "scan":
      return routine ? "host · scan signatures" : "host · scanned";
    case "first_time":
      return routine ? "host · new alert types" : "host · first-time alert types";
    case "volume":
      return routine ? "host · recurring burst" : "host · alert burst";
    default:
      return incident.kind === "actor" ? "source IP" : "host";
  }
}

export function narrative(incident: Incident, byId: Map<string, RankedIncident>): Narrative {
  const family = featureFamily(incident);
  const p = incident.model?.p_max;
  const routine = p == null || p < CONFIRMED_THRESHOLD;
  const x = extract(incident);
  const mins = minutesBetween(incident.start, incident.end);
  const alerts = n(incident.n_alerts);
  const entity = incident.entity;
  const rules = incident.top_rules.slice(0, 2).map((r) => ruleName(r.detector));
  const rel = relatedTimeline(incident, byId);
  const near = sameEntityNeighbours(incident, byId);
  const later = near.filter((r) => r.offsetMin > 0)[0];
  const earlier = [...near.filter((r) => r.offsetMin < 0)].reverse()[0];
  const concurrent = rel
    .filter((r) => Math.abs(r.offsetMin) <= 5 && !r.sameEntity)
    .map((r) => r.id);
  const modelLine =
    p == null
      ? "No model score is available for this incident; the ranking is statistical only."
      : routine
        ? `The model scored it ${p.toFixed(2)}, which does not look like attack activity.`
        : `The model scored it ${p.toFixed(2)}.`;
  const top = dominantFeatures(incident)[0] ?? "total";
  const toolNote = x.tools.length ? ` The user agent names ${list(x.tools)}.` : "";
  const sourceNote = x.sources.length ? ` Sample alerts come from ${list(x.sources)}.` : "";
  const userNote = x.users.length ? ` Accounts seen: ${list(x.users)}.` : "";
  const pathNote = x.paths.length ? ` Paths mentioned: ${list(x.paths)}.` : "";
  const followOn = later
    ? ` ${later.offsetMin} minutes later the same ${incident.kind === "actor" ? "source" : "host"} shows ${later.id} (${shortLabel(later.incident)}).`
    : "";
  const precededBy = earlier
    ? ` It follows ${earlier.id} on the same ${incident.kind === "actor" ? "source" : "host"} by ${-earlier.offsetMin} minutes.`
    : "";
  const sameTime = concurrent.length
    ? ` ${list(concurrent)} fired on other hosts in the same minutes.`
    : "";
  const ruleNote = rules.length ? ` Most alerts were ${list(rules)}.` : "";

  const base = { family, routine, label: shortLabel(incident) };

  switch (family) {
    case "entry_point":
      return {
        ...base,
        headline: routine
          ? `Routine traffic from ${entity}`
          : `Attack traffic entered through ${entity}`,
        summary:
          `${entity} is the source of ${alerts} alerts across ${incident.targets?.length ?? "several"} hosts in ${mins} minutes.${ruleNote}${toolNote}` +
          ` A source address seen by the sensors can be a gateway, VPN or firewall rather than the attacker's own machine.${sameTime} ${modelLine}`,
        risks: routine
          ? ["Low on its own. The same source carries ordinary traffic on other days."]
          : [
              "Everything this address forwards reaches internal servers.",
              "If it is a gateway, the attacker's real address is hidden behind it.",
            ],
        blind: routine
          ? null
          : "The attacker's true external address does not appear in these alerts if this is a gateway.",
        steps: routine
          ? [
              "Confirm the traffic matches a known service or scheduled job",
              "Dismiss as routine if it does",
            ]
          : [
              `Pull NAT and connection logs on ${entity} for ${clockUtc(incident.start)} to ${clockUtc(incident.end)} UTC`,
              "Identify the external address behind the attack traffic and block it at the edge",
              `Check which internal hosts it reached${incident.targets?.length ? ` (${incident.targets.slice(0, 5).join(", ")}${incident.targets.length > 5 ? ", …" : ""})` : ""}`,
              "Confirm the gateway itself was not compromised",
            ],
      };
    case "web_attack":
      return {
        ...base,
        headline: routine ? `Web noise on ${entity}` : `Web attack against ${entity}`,
        summary:
          `In ${mins} minutes ${entity} produced ${alerts} alerts.${ruleNote}${toolNote}${sourceNote}` +
          (routine
            ? " "
            : " This pattern is automated scanning or brute forcing of the web application. ") +
          `${followOn}${modelLine}`,
        risks: routine
          ? ["Low. Web error bursts like this recur without an attack behind them."]
          : [
              later
                ? `This server is the target: ${later.id} follows on the same host.`
                : "This server is the target of the scan; a successful exploit gives code execution as the web server account.",
              "Brute-forced logins or an uploaded webshell are the usual next step.",
            ],
        blind: null,
        steps: routine
          ? ["Check the source is a known scanner or monitor", "Dismiss as routine if it is"]
          : [
              `Pull web access logs for ${clockUtc(incident.start)} to ${clockUtc(incident.end)} UTC and list requests that returned 200 inside the error burst`,
              "Check the upload directories for files created in that window",
              x.sources.length
                ? `Trace ${x.sources[0]} to its real origin (see the related source-IP incident)`
                : "Find the source behind the traffic in the gateway logs",
              "Block or rate-limit that source at the edge",
              later
                ? `Review ${later.id} for follow-on activity`
                : "Watch this host for logins or privilege use in the next hour",
            ],
      };
    case "privilege":
      return {
        ...base,
        headline: routine
          ? `Login on ${entity}, likely routine`
          : x.elevatedTo.length
            ? `Privilege escalation on ${entity}`
            : `Unusual login or privilege use on ${entity}`,
        summary: `${top === "auth_fail" ? "Failed logins spiked" : "A login or privilege use that is rare for this host appeared"} on ${entity}.${userNote}${x.elevatedTo.length ? ` Privileges were raised to ${list(x.elevatedTo)}.` : ""}${pathNote}${precededBy}${sameTime} ${modelLine}`,
        risks: routine
          ? [
              "Probably planned maintenance, but an unexplained admin login is worth one confirmation.",
            ]
          : [
              earlier
                ? `It follows ${earlier.id} on the same host, which is the pattern of an attacker using a foothold.`
                : "Interactive access that this host does not normally see.",
              x.users.length
                ? `The ${list(x.users)} account${x.users.length > 1 ? "s" : ""} should be treated as compromised until confirmed.`
                : "The account involved should be confirmed with its owner.",
            ],
        blind:
          routine || !earlier
            ? null
            : "How the credentials were obtained is not visible. Offline password cracking leaves no trace in IDS alerts.",
        steps: routine
          ? [
              x.users.length
                ? `Confirm with ${list(x.users, "or")} or the change log that this was planned`
                : "Confirm with the change log that this was planned",
              "If confirmed, dismiss as routine",
              "If not, treat it as suspicious access and reset the account",
            ]
          : [
              `Isolate ${entity} from the network`,
              "Image the host before making changes",
              x.users.length
                ? `Disable ${list(x.users)} and rotate every credential used on this server`
                : "Rotate every credential used on this server",
              x.paths.length
                ? `Inspect ${x.paths[0]} for a webshell or dropped files`
                : "Search the web root and temp directories for files created in the last hour",
              `Review auth and audit logs for ${clockUtc(incident.start)} UTC onward`,
            ],
      };
    case "scan":
      return {
        ...base,
        headline: routine ? `Scan signatures on ${entity}` : `${entity} probed by a scanner`,
        summary: `Network-scan signatures fired for ${entity} over ${mins} minutes (${alerts} alerts).${ruleNote}${sourceNote}${sameTime} ${modelLine}`,
        risks: routine
          ? ["Low. Scanning noise recurs on exposed hosts."]
          : ["Probing comes before exploitation; a vulnerable service here is the next target."],
        blind: null,
        steps: routine
          ? ["Confirm the source is an authorised scanner", "Dismiss as routine if it is"]
          : [
              "Check whether any request to this host succeeded",
              `Confirm there are no new logins or processes after ${clockUtc(incident.start)} UTC`,
              "If it was only scanned, close it together with the source-IP incident",
            ],
      };
    case "first_time":
      return {
        ...base,
        headline: routine ? `New alert types on ${entity}` : `First-time alert types on ${entity}`,
        summary: `Alert types this host had never shown appeared on ${entity}${sameTime ? "," : "."}${sameTime}${ruleNote}${sourceNote}${precededBy} ${modelLine}`,
        risks: routine
          ? ["Low unless the new types keep appearing."]
          : [
              "New behaviour in the same minutes as the attack usually means the host was probed by the same source.",
            ],
        blind: null,
        steps: routine
          ? ["Read the new alert types once; no action unless they recur"]
          : [
              "Check whether any request to this host succeeded",
              `Confirm there are no new logins or processes after ${clockUtc(incident.start)} UTC`,
              "If it was only scanned, close it together with the source-IP incident",
            ],
      };
    case "volume":
      return {
        ...base,
        headline: routine ? `Recurring alert burst on ${entity}` : `Alert burst on ${entity}`,
        summary: `${alerts} alerts in ${mins} minutes on ${entity}, far above its normal rate.${ruleNote}${sourceNote}${precededBy}${followOn} ${modelLine}`,
        risks: routine
          ? ["Low. The same pattern repeats on ordinary days."]
          : ["A burst this size on a host that is normally quiet needs a named cause."],
        blind: null,
        steps: routine
          ? [
              "No action unless it starts showing new alert types",
              "Consider tuning the noisiest rule",
            ]
          : [
              "Read the top rules and name the process behind them",
              "Compare with the same hour on the previous day",
              "Open the related incidents in time order",
            ],
      };
    default:
      return {
        ...base,
        headline: `Anomalous minutes on ${entity}`,
        summary: `${alerts} alerts in ${mins} minutes on ${entity}.${ruleNote}${sourceNote} ${modelLine}`,
        risks: ["Unclassified. Read the evidence below before deciding."],
        blind: null,
        steps: ["Read the sample alerts", "Open the related incidents", "Decide and note why"],
      };
  }
}

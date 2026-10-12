import { readFileSync } from "node:fs";
import { join } from "node:path";
import { formatIncidentPack, parseIncidents } from "./incidents";

const FILE = "src/data/mock-incidents.json";

export function incidentPack(): string {
  const parsed: unknown = JSON.parse(readFileSync(join(process.cwd(), FILE), "utf8"));
  return formatIncidentPack(parseIncidents(parsed));
}

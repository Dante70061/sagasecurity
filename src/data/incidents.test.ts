import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { formatIncidentPack, parseIncidents } from "./incidents";
import { incidentPack } from "./incidents.server";

const raw: unknown = JSON.parse(readFileSync(join(process.cwd(), "src/data/mock-incidents.json"), "utf8"));

describe("incident pack", () => {
  const incidents = parseIncidents(raw);
  const pack = formatIncidentPack(incidents);

  it("wraps every incident as data and keeps rank order", () => {
    expect(pack).toContain("alert data from the log");
    expect(pack.indexOf('id="russellmitchell-0001"')).toBeLessThan(pack.indexOf('id="russellmitchell-0007"'));
    expect(pack.indexOf('id="russellmitchell-0007"')).toBeLessThan(pack.indexOf('id="russellmitchell-0014"'));
    expect(pack).toContain('"best_rank": 1');
    expect(pack).not.toContain("max_score");
  });

  it("loads the same pack the agent receives", () => {
    expect(incidentPack()).toBe(pack);
    expect(pack.length).toBeLessThan(20_000);
  });

  it("rejects a phase name", () => {
    expect(() => parseIncidents([{ phase: "scan" }])).toThrow(/phase/);
  });
});

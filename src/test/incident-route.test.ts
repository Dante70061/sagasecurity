import { describe, expect, it } from "vitest";

import { parseIncidentRef } from "@/data/incidents";
import { assertNoLabels, buildIncidentPage } from "@/data/incidents.server";

describe("incident page loader", () => {
  it("returns the incident with its run's queue, label-free, with related links inside the queue", async () => {
    const view = await buildIncidentPage("INC-0001", "wilson_test");
    expect(view).not.toBeNull();
    expect(view!.incident.incident_id).toBe("INC-0001");
    expect(view!.queue.run).toBe("wilson_test");
    expect(() => assertNoLabels(view)).not.toThrow();
    const ids = new Set(view!.queue.incidents.map((i) => i.incident_id));
    for (const id of view!.incident.related) expect(ids.has(id)).toBe(true);
    expect(view!.queue.summary?.raw_alerts).toBe(633021);
    expect(view!.queue.summary?.alerts_by_sensor).toEqual({
      wazuh: 427607,
      suricata: 54481,
      aminer: 8212,
    });
  });

  it("returns null for an id outside the run and rejects malformed ids", async () => {
    expect(await buildIncidentPage("INC-9999", "wilson_test")).toBeNull();
    expect(() => parseIncidentRef({ id: "../etc/passwd" })).toThrow();
    expect(parseIncidentRef({ id: "INC-0002", run: "dev", scenario: "fox" })).toEqual({
      id: "INC-0002",
      run: "dev",
      scenario: "fox",
    });
  });
});

import { describe, expect, it } from "vitest";

import type { Incident } from "@/data/incidents";
import { parseSelection } from "@/data/incidents";
import {
  assertNoLabels,
  buildQueueView,
  describeIncident,
  evidencePackFor,
  groupOf,
  pruneRelated,
  rankIncidents,
} from "@/data/incidents.server";

function fake(
  id: string,
  peak_z: number,
  p_max: number | null,
  extra: Partial<Incident> = {},
): Incident {
  return {
    run: "t",
    incident_id: id,
    kind: "host",
    scenario: "s",
    entity: "10.0.0.1",
    start: "2022-01-01T00:00:00+00:00",
    end: "2022-01-01T00:10:00+00:00",
    peak_z,
    n_windows: 10,
    n_alerts: 100,
    tools: ["wazuh"],
    targets: null,
    reasons: [{ feature: "total", z: peak_z, text: "alert volume far above its normal" }],
    top_rules: [],
    sample_alerts: [],
    related: [],
    model:
      p_max == null
        ? null
        : { score_col: "p_attack", n_minutes: 10, p_max, p_mean: p_max, peak_minute_utc: null },
    ...extra,
  };
}

describe("incident ranking", () => {
  it("groups confirmed first, then below threshold, then unscored, each by peak_z descending", () => {
    const ranked = rankIncidents(
      [
        fake("A", 5, 0.2),
        fake("B", 50, 0.9),
        fake("C", 9, null),
        fake("D", 30, 0.5),
        fake("E", 60, 0.1),
        fake("F", 99, null),
      ],
      "t",
    );
    expect(ranked.map((i) => i.incident_id)).toEqual(["B", "D", "E", "A", "F", "C"]);
    expect(ranked.map((i) => i.group)).toEqual([
      "confirmed",
      "confirmed",
      "below",
      "below",
      "unscored",
      "unscored",
    ]);
    expect(ranked.map((i) => i.rank)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("never sorts by p_max inside a group", () => {
    const ranked = rankIncidents([fake("low-p", 40, 0.51), fake("high-p", 20, 1.0)], "t");
    expect(ranked.map((i) => i.incident_id)).toEqual(["low-p", "high-p"]);
  });

  it("treats a null model as unscored", () => {
    expect(groupOf(fake("x", 1, null))).toBe("unscored");
    expect(groupOf(fake("x", 1, 0.5))).toBe("confirmed");
    expect(groupOf(fake("x", 1, 0.4999))).toBe("below");
  });

  it("filters by run and scenario", () => {
    const rows = [
      fake("A", 1, 1),
      fake("B", 2, 1, { run: "other" }),
      fake("C", 3, 1, { scenario: "z" }),
    ];
    expect(rankIncidents(rows, "t").map((i) => i.incident_id)).toEqual(["C", "A"]);
    expect(rankIncidents(rows, "t", "s").map((i) => i.incident_id)).toEqual(["A"]);
  });
});

describe("related pruning", () => {
  it("drops related ids that are not in the same run's hand-off set", () => {
    const rows = pruneRelated([
      fake("A", 1, 1, { related: ["B", "GHOST", "A"] }),
      fake("B", 1, 1, { related: ["A", "C"] }),
      fake("C", 1, 1, { run: "other", related: ["A"] }),
    ]);
    expect(rows.map((i) => i.related)).toEqual([["B"], ["A"], []]);
  });

  it("leaves no dangling related id in the committed snapshot", async () => {
    const view = await buildQueueView("wilson_test");
    const ids = new Set(view.incidents.map((i) => i.incident_id));
    for (const i of view.incidents) for (const id of i.related) expect(ids.has(id)).toBe(true);
    expect(view.incidents.some((i) => i.related.length > 0)).toBe(true);
  });
});

describe("committed snapshot", () => {
  it("opens on wilson_test with INC-0001..0004 at the top", async () => {
    const view = await buildQueueView();
    expect(view.run).toBe("wilson_test");
    expect(view.scenario).toBe("wilson");
    expect(view.incidents.slice(0, 4).map((i) => i.incident_id)).toEqual([
      "INC-0001",
      "INC-0002",
      "INC-0003",
      "INC-0004",
    ]);
    expect(view.counts.confirmed).toBeGreaterThan(0);
    expect(view.summary?.alerts).toBeGreaterThan(0);
    for (let n = 1; n < view.incidents.length; n += 1) {
      const a = view.incidents[n - 1]!;
      const b = view.incidents[n]!;
      if (a.group === b.group) expect(a.peak_z).toBeGreaterThanOrEqual(b.peak_z);
    }
  });

  it("offers the dev run with seven scenarios", async () => {
    const view = await buildQueueView("dev", "fox");
    expect(view.scenarios).toHaveLength(7);
    expect(view.scenario).toBe("fox");
    expect(view.incidents.every((i) => i.scenario === "fox")).toBe(true);
  });
});

describe("evidence pack", () => {
  it("cites incident ids, carries reasons and samples, and contains no labels", async () => {
    const pack = await evidencePackFor("wilson_test", undefined, 10);
    expect(pack).toContain("[INC-0001]");
    expect(pack).toContain("confirmed by model");
    expect(pack).toContain("why flagged:");
    expect(pack).toContain("sample:");
    expect(pack).toContain("related incidents:");
    expect(pack.toLowerCase()).not.toContain("label");
    expect(pack.toLowerCase()).not.toContain("phase");
    expect((pack.match(/^\[INC-/gm) ?? []).length).toBe(10);
  });

  it("says when the model score is unavailable", () => {
    const text = describeIncident({ ...fake("Z", 3, null), rank: 1, group: "unscored" });
    expect(text).toContain("model score unavailable");
  });
});

describe("label guard", () => {
  it("rejects a phase name and any label field", () => {
    expect(() => assertNoLabels([{ phase: "scan" }])).toThrow(/phase/);
    expect(() => assertNoLabels({ a: [{ label_is_attack: 1 }] })).toThrow(/label_is_attack/);
    expect(() => assertNoLabels({ reasons: [{ feature: "x", z: 1, text: "t" }] })).not.toThrow();
  });
});

describe("selection parsing", () => {
  it("accepts short names and rejects junk", () => {
    expect(parseSelection({ run: "dev", scenario: "fox" })).toEqual({
      run: "dev",
      scenario: "fox",
    });
    expect(parseSelection(undefined)).toEqual({});
    expect(() => parseSelection({ run: "../etc" })).toThrow();
    expect(() => parseSelection({ scenario: 42 })).toThrow();
  });
});

import { describe, expect, it } from "vitest";

import type { Incident, RankedIncident } from "@/data/incidents";
import { buildQueueView } from "@/data/incidents.server";
import { extract, featureFamily, narrative, riskLevel, shortLabel } from "@/data/triage";

function fake(partial: Partial<Incident> & { id: string }): RankedIncident {
  const { id, ...rest } = partial;
  const p = rest.model === null ? null : (rest.model?.p_max ?? 1);
  return {
    run: "t",
    incident_id: id,
    kind: "host",
    scenario: "s",
    entity: "10.0.0.9",
    start: "2022-02-07T10:59:00+00:00",
    end: "2022-02-07T11:21:00+00:00",
    peak_z: 20,
    n_windows: 22,
    n_alerts: 1000,
    tools: ["wazuh"],
    targets: null,
    reasons: [{ feature: "total", z: 20, text: "alert volume far above its normal" }],
    top_rules: [],
    sample_alerts: [],
    related: [],
    model:
      p == null
        ? null
        : { score_col: "p_attack", n_minutes: 22, p_max: p, p_mean: p, peak_minute_utc: null },
    rank: 1,
    group: p == null ? "unscored" : p >= 0.5 ? "confirmed" : "below",
    ...rest,
  };
}

describe("risk level", () => {
  it("is high only when confirmed and peak z >= 12, medium when confirmed, low otherwise", () => {
    expect(riskLevel(fake({ id: "a", peak_z: 49.3 }))).toBe("high");
    expect(riskLevel(fake({ id: "b", peak_z: 12 }))).toBe("high");
    expect(riskLevel(fake({ id: "c", peak_z: 11.9 }))).toBe("medium");
    expect(
      riskLevel(
        fake({
          id: "d",
          peak_z: 99,
          model: {
            score_col: "p_attack",
            n_minutes: 1,
            p_max: 0.49,
            p_mean: 0.1,
            peak_minute_utc: null,
          },
        }),
      ),
    ).toBe("low");
    expect(riskLevel(fake({ id: "e", peak_z: 99, model: null }))).toBe("low");
  });

  it("matches the wilson snapshot: INC-0001..0003 high, INC-0004 medium, below-threshold low", async () => {
    const view = await buildQueueView("wilson_test");
    const by = new Map(view.incidents.map((i) => [i.incident_id, i]));
    expect(["INC-0001", "INC-0002", "INC-0003"].map((id) => riskLevel(by.get(id)!))).toEqual([
      "high",
      "high",
      "high",
    ]);
    expect(riskLevel(by.get("INC-0004")!)).toBe("medium");
    for (const i of view.incidents) if (i.group === "below") expect(riskLevel(i)).toBe("low");
  });
});

describe("template selection", () => {
  it("picks the family from kind and dominant feature", () => {
    expect(featureFamily(fake({ id: "a", kind: "actor" }))).toBe("entry_point");
    expect(
      featureFamily(fake({ id: "b", reasons: [{ feature: "web_attack", z: 9, text: "" }] })),
    ).toBe("web_attack");
    expect(
      featureFamily(
        fake({
          id: "c",
          reasons: [{ feature: "high_level", z: 9, text: "" }],
          top_rules: [{ tool: "wazuh", detector: "31101: Web server 400 error code.", count: 5 }],
        }),
      ),
    ).toBe("web_attack");
    expect(
      featureFamily(fake({ id: "d", reasons: [{ feature: "auth_success", z: 9, text: "" }] })),
    ).toBe("privilege");
    expect(
      featureFamily(fake({ id: "e", reasons: [{ feature: "new_rule", z: 9, text: "" }] })),
    ).toBe("first_time");
    expect(
      featureFamily(
        fake({
          id: "f",
          reasons: [
            { feature: "new_rule", z: 9, text: "" },
            { feature: "priv", z: 4, text: "" },
          ],
        }),
      ),
    ).toBe("privilege");
    expect(
      featureFamily(fake({ id: "g", reasons: [{ feature: "sig_scan", z: 9, text: "" }] })),
    ).toBe("scan");
    expect(featureFamily(fake({ id: "h", reasons: [{ feature: "total", z: 9, text: "" }] }))).toBe(
      "volume",
    );
    expect(featureFamily(fake({ id: "i", reasons: [] }))).toBe("other");
  });

  it("labels routine when below threshold", () => {
    const below = fake({
      id: "a",
      kind: "actor",
      model: {
        score_col: "p_attack",
        n_minutes: 1,
        p_max: 0.1,
        p_mean: 0.1,
        peak_minute_utc: null,
      },
    });
    expect(shortLabel(below)).toContain("routine");
    expect(narrative(below, new Map()).routine).toBe(true);
  });

  it("fills real values and never invents users, paths or tools", () => {
    const inc = fake({
      id: "INC-0003",
      entity: "172.26.243.167",
      reasons: [
        { feature: "rare_rule", z: 13.9, text: "rare" },
        { feature: "priv", z: 5, text: "sudo" },
      ],
      sample_alerts: [
        {
          ts: "2022-02-07T11:48:00+00:00",
          tool: "wazuh",
          detector: "5402: Successful sudo to ROOT executed.",
          level: 3,
          src_ip: null,
          dst_ip: null,
          raw: "Feb  7 11:48:11 intranet sudo:  jwilkinson : TTY=pts/0 ; PWD=/var/www/intranet/wp-content/uploads/2022/02 ; USER=root ; COMMAND=/usr/bin/id",
        },
        {
          ts: "2022-02-07T11:48:00+00:00",
          tool: "wazuh",
          detector: "5304: Successful su",
          level: 3,
          src_ip: null,
          dst_ip: null,
          raw: "Feb  7 11:48:02 intranet su: Successful su for jwilkinson by www-data",
        },
      ],
    });
    const x = extract(inc);
    expect(x.users).toEqual(expect.arrayContaining(["jwilkinson", "www-data"]));
    expect(x.elevatedTo).toContain("root");
    expect(x.paths[0]).toContain("/wp-content/uploads/2022/02");
    const story = narrative(inc, new Map());
    expect(story.family).toBe("privilege");
    expect(story.headline).toContain("172.26.243.167");
    expect(story.summary).toContain("jwilkinson");
    expect(story.steps.some((s) => s.includes("/wp-content/uploads/2022/02"))).toBe(true);

    const bare = narrative(
      fake({ id: "x", reasons: [{ feature: "auth_success", z: 9, text: "" }] }),
      new Map(),
    );
    expect(bare.summary).not.toMatch(/jwilkinson|www-data|ckhan/);
    expect(bare.steps.join(" ")).not.toMatch(/wp-content/);
  });

  it("names the credential blind spot only when a prior incident on the same host exists", () => {
    const earlier = fake({
      id: "INC-0001",
      entity: "h",
      start: "2022-02-07T10:59:00+00:00",
      end: "2022-02-07T11:21:00+00:00",
    });
    const later = fake({
      id: "INC-0003",
      entity: "h",
      start: "2022-02-07T11:48:00+00:00",
      end: "2022-02-07T11:49:00+00:00",
      reasons: [{ feature: "priv", z: 13, text: "" }],
      related: ["INC-0001"],
    });
    const byId = new Map([[earlier.incident_id, earlier]]);
    expect(narrative(later, byId).blind).toMatch(/Offline password cracking/);
    expect(narrative(later, new Map()).blind).toBeNull();
    expect(narrative(later, byId).summary).toContain("follows INC-0001");
  });
});

describe("follow-on incidents", () => {
  it("links a same-host incident 27 minutes later even though related[] does not", () => {
    const earlier = fake({
      id: "INC-0001",
      entity: "h",
      start: "2022-02-07T10:59:00+00:00",
      end: "2022-02-07T11:21:00+00:00",
    });
    const later = fake({
      id: "INC-0003",
      entity: "h",
      start: "2022-02-07T11:48:00+00:00",
      end: "2022-02-07T11:49:00+00:00",
      reasons: [{ feature: "priv", z: 13, text: "" }],
    });
    const byId = new Map([[earlier.incident_id, earlier]]);
    expect(narrative(later, byId).summary).toContain("follows INC-0001");
    expect(narrative(later, byId).blind).toMatch(/Offline password cracking/);
    const farAway = fake({
      ...earlier,
      id: "INC-0009",
      start: "2022-02-05T10:59:00+00:00",
      end: "2022-02-05T11:00:00+00:00",
    });
    expect(narrative(later, new Map([[farAway.incident_id, farAway]])).blind).toBeNull();
  });

  it("builds INC-0003's story from the wilson snapshot without pam noise as an account", async () => {
    const view = await buildQueueView("wilson_test");
    const byId = new Map(view.incidents.map((i) => [i.incident_id, i]));
    const inc = byId.get("INC-0003")!;
    const story = narrative(inc, byId);
    expect(story.family).toBe("privilege");
    expect(story.summary).toContain("follows INC-0001");
    expect(story.blind).toMatch(/Offline password cracking/);
    expect(extract(inc).users.join(" ")).not.toMatch(/pam_unix|\(/);
    expect(extract(inc).users).toContain("jwilkinson");
  });
});

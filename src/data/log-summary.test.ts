import { describe, expect, it } from "vitest";
import { readLogSummary } from "./log-summary.server";

describe("busiest hour", () => {
  const view = readLogSummary().view;

  it("uses the hour with the most rows and accounts for every row in it", () => {
    const peak = view.hours.reduce((best, point) => (point.events > best.events ? point : best));
    expect(view.days).toHaveLength(4);
    expect(view.peakHour.total).toBe(peak.events);
    expect(view.peakHour.label.startsWith(peak.time)).toBe(true);
    expect(view.peakHour.detectors.reduce((sum, row) => sum + row.count, 0)).toBe(peak.events);
    expect(view.peakHour.detectors[0]?.detector).toContain("31101");
    const counts = view.peakHour.detectors.map((row) => row.count);
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
    expect(view.distribution.reduce((sum, row) => sum + row.count, 0)).toBe(view.events);
  });
});

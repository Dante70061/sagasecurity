import { describe, expect, it } from "vitest";

import {
  EMPTY_STATE,
  parseState,
  readDecisions,
  readState,
  storageKey,
  writeState,
} from "@/lib/triage-storage";

function memoryStore() {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
  };
}

const throwing = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
  removeItem: () => {
    throw new Error("blocked");
  },
};

describe("triage storage", () => {
  it("round-trips state per run and incident", () => {
    const store = memoryStore();
    const state = {
      checks: [true, false, true],
      decision: "escalate" as const,
      notes: "checked logs",
    };
    expect(writeState("wilson_test", "INC-0001", state, store)).toBe(true);
    expect(readState("wilson_test", "INC-0001", store)).toEqual(state);
    expect(readState("dev", "INC-0001", store)).toEqual(EMPTY_STATE);
    expect(storageKey("wilson_test", "INC-0001")).toBe(
      "saga-security-triage-v2:wilson_test:INC-0001",
    );
  });

  it("falls back to the empty state when storage throws, is missing, or holds junk", () => {
    expect(readState("r", "INC-0001", throwing)).toEqual(EMPTY_STATE);
    expect(writeState("r", "INC-0001", { ...EMPTY_STATE, notes: "x" }, throwing)).toBe(false);
    expect(readState("r", "INC-0001", null)).toEqual(EMPTY_STATE);
    expect(writeState("r", "INC-0001", { ...EMPTY_STATE, notes: "x" }, null)).toBe(false);
    const store = memoryStore();
    store.setItem(storageKey("r", "INC-0002"), "{not json");
    expect(readState("r", "INC-0002", store)).toEqual(EMPTY_STATE);
    expect(parseState({ checks: [1, true, "yes"], decision: "nuke", notes: 42 })).toEqual({
      checks: [false, true, false],
      decision: null,
      notes: "",
    });
  });

  it("removes the record when everything is cleared and lists decisions for a run", () => {
    const store = memoryStore();
    writeState("r", "INC-0001", { checks: [], decision: "monitor", notes: "" }, store);
    writeState("r", "INC-0002", { checks: [true], decision: null, notes: "" }, store);
    expect([...readDecisions("r", ["INC-0001", "INC-0002", "INC-0003"], store).entries()]).toEqual([
      ["INC-0001", "monitor"],
    ]);
    writeState("r", "INC-0001", EMPTY_STATE, store);
    expect(store.map.has(storageKey("r", "INC-0001"))).toBe(false);
  });
});

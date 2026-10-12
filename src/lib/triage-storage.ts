// Per-incident analyst state (checked steps, decision, notes) kept in this browser only.
// Key prefix follows the assistant's v2 storage key. Every read and write is guarded: a private
// window, blocked storage or corrupt JSON must never break the page, it just loses persistence.

export type Decision = "escalate" | "monitor" | "dismiss";

export type TriageState = {
  checks: boolean[];
  decision: Decision | null;
  notes: string;
};

export const DECISIONS: { key: Decision; label: string }[] = [
  { key: "escalate", label: "Escalate" },
  { key: "monitor", label: "Monitor" },
  { key: "dismiss", label: "Dismiss as routine" },
];

export const STORAGE_PREFIX = "saga-security-triage-v2";

export const EMPTY_STATE: TriageState = { checks: [], decision: null, notes: "" };

export function storageKey(run: string, incidentId: string): string {
  return `${STORAGE_PREFIX}:${run}:${incidentId}`;
}

function isDecision(value: unknown): value is Decision {
  return value === "escalate" || value === "monitor" || value === "dismiss";
}

/** Accepts only the shape we wrote; anything else degrades to the empty state. */
export function parseState(raw: unknown): TriageState {
  if (typeof raw !== "object" || raw === null) return EMPTY_STATE;
  const v = raw as Record<string, unknown>;
  const checks = Array.isArray(v["checks"]) ? v["checks"].map((c) => c === true) : [];
  const decision = isDecision(v["decision"]) ? v["decision"] : null;
  const notes = typeof v["notes"] === "string" ? v["notes"].slice(0, 4000) : "";
  return { checks, decision, notes };
}

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storage(): StorageLike | null {
  try {
    if (typeof window === "undefined" || !window.localStorage) return null;
    return window.localStorage;
  } catch {
    return null;
  }
}

export function readState(
  run: string,
  incidentId: string,
  store: StorageLike | null = storage(),
): TriageState {
  try {
    const raw = store?.getItem(storageKey(run, incidentId));
    if (!raw) return EMPTY_STATE;
    return parseState(JSON.parse(raw));
  } catch {
    return EMPTY_STATE;
  }
}

/** Returns true when the state was persisted, false when storage was unavailable or threw. */
export function writeState(
  run: string,
  incidentId: string,
  state: TriageState,
  store: StorageLike | null = storage(),
): boolean {
  try {
    if (!store) return false;
    const empty = !state.checks.some(Boolean) && !state.decision && !state.notes.trim();
    if (empty) store.removeItem(storageKey(run, incidentId));
    else store.setItem(storageKey(run, incidentId), JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

/** Decisions for a whole run, used for the "N of M decided" counter and the nav labels. */
export function readDecisions(
  run: string,
  incidentIds: string[],
  store: StorageLike | null = storage(),
): Map<string, Decision> {
  const out = new Map<string, Decision>();
  for (const id of incidentIds) {
    const decision = readState(run, id, store).decision;
    if (decision) out.set(id, decision);
  }
  return out;
}

export function decisionLabel(decision: Decision | null | undefined): string {
  return DECISIONS.find((d) => d.key === decision)?.label ?? "";
}

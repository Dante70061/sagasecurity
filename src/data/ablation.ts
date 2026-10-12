// Ablation results shown on the console. These are evaluation aggregates over the 7 development
// scenarios (leave-one-scenario-out, wilson never loaded), NOT per-incident data, and they are not in
// incidents_scored.json. Source of every number: outputs/ablation/README.md (scripts/ablation_loso.py).
// Update this file by hand when that README changes.

export const ABLATION_SOURCE = "outputs/ablation/README.md";

export type AblationArm = {
  key: "his" | "his+st" | "st";
  label: string;
  features: number;
  meanAP: number;
  worstAP: number;
  recallAt1pct: number;
  phasesCaught: number;
  phasesTotal: number;
  falsePositivesAt1pct: number;
};

export const ABLATION_ARMS: readonly AblationArm[] = [
  {
    key: "his",
    label: "Network-wide features only",
    features: 35,
    meanAP: 0.828,
    worstAP: 0.637,
    recallAt1pct: 0.862,
    phasesCaught: 41,
    phasesTotal: 42,
    falsePositivesAt1pct: 394,
  },
  {
    key: "his+st",
    label: "+ per-host statistics",
    features: 61,
    meanAP: 0.907,
    worstAP: 0.804,
    recallAt1pct: 0.954,
    phasesCaught: 40,
    phasesTotal: 42,
    falsePositivesAt1pct: 390,
  },
  {
    key: "st",
    label: "Per-host statistics only",
    features: 26,
    meanAP: 0.901,
    worstAP: 0.706,
    recallAt1pct: 0.951,
    phasesCaught: 40,
    phasesTotal: 42,
    falsePositivesAt1pct: 391,
  },
];

export const ABLATION_NOTE =
  "7 development scenarios, leave-one-scenario-out · wilson never used · 112 positive minutes, so differences are directional";

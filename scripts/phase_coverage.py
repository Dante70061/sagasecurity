#!/usr/bin/env python3
"""Evaluation for slides only (never shown in the UI): per labeled attack phase, which incident found it.

For every labeled phase in dataset/labels.csv, take the best-ranked incident in
outputs[/wilson_test]/incidents_eval.csv whose `phases` column includes it (the stats stage marks
overlap with a 2-minute tolerance), and report its rank out of the scenario's full incident list,
whether it made the top-40 hand-off (in_budget), and whether the window model confirmed it
(p_attack >= 0.5 in incidents_scored.json; incidents outside the hand-off were never scored).

Writes outputs/phase_coverage.txt: a per-phase table for wilson and a per-scenario summary for
the 7 dev scenarios. Reads only evaluation outputs; touches nothing the app uses.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
THRESHOLD = 0.5


def load_run(run_dir: Path, run: str, scored: dict) -> pd.DataFrame:
    ev = pd.read_csv(run_dir / "incidents_eval.csv")
    ev["phases"] = ev["phases"].fillna("").astype(str)
    ev["p_max"] = [scored.get((run, i)) for i in ev["incident_id"]]
    ev["n_in_scenario"] = ev.groupby("scenario")["incident_id"].transform("size")
    return ev


def coverage(ev: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, p in labels.iterrows():
        hits = ev[(ev.scenario == p.scenario) & ev.phases.str.split(",").apply(lambda ps: p.attack in ps)]
        if hits.empty:
            rows.append({"scenario": p.scenario, "phase": p.attack, "incident": "—", "rank": None,
                         "of": int(ev.loc[ev.scenario == p.scenario, "n_in_scenario"].iloc[0]) if (ev.scenario == p.scenario).any() else 0,
                         "top40": "no", "confirmed": "—", "p_attack": None, "entity": "", "kind": ""})
            continue
        best = hits.sort_values("rank_in_scenario").iloc[0]
        pm = best.p_max
        rows.append({"scenario": p.scenario, "phase": p.attack, "incident": best.incident_id,
                     "rank": int(best.rank_in_scenario), "of": int(best.n_in_scenario),
                     "top40": "yes" if bool(best.in_budget) else "no",
                     "confirmed": "—" if pm is None or pd.isna(pm) else ("yes" if pm >= THRESHOLD else "no"),
                     "p_attack": None if pm is None or pd.isna(pm) else round(float(pm), 3),
                     "entity": best.entity, "kind": best.kind})
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outputs", type=Path, default=ROOT / "outputs")
    ap.add_argument("--labels", type=Path, default=ROOT / "dataset" / "labels.csv")
    ap.add_argument("--scored", type=Path, default=ROOT / "outputs" / "incidents_scored.json")
    ap.add_argument("--out", type=Path, default=ROOT / "outputs" / "phase_coverage.txt")
    a = ap.parse_args()

    scored = {(i["run"], i["incident_id"]): (i["model"] or {}).get("p_max") for i in json.loads(a.scored.read_text())}
    labels = pd.read_csv(a.labels)
    lines = [f"Phase coverage · {datetime.now():%Y-%m-%d %H:%M} · evaluation only, not shown in the UI",
             "rank = position in the scenario's full incident list (statistics only); top40 = handed off; "
             f"confirmed = model p_attack >= {THRESHOLD} (only hand-off incidents are scored)", ""]
    pd.set_option("display.width", 200)

    wil = coverage(load_run(a.outputs / "wilson_test", "wilson_test", scored), labels[labels.scenario == "wilson"])
    lines.append("=== wilson (held-out) ===")
    lines.append(wil[["phase", "incident", "kind", "entity", "rank", "of", "top40", "confirmed", "p_attack"]].to_string(index=False))
    lines.append(f"phases {len(wil)} · found by any incident {int((wil['rank'].notna()).sum())} · in top 40 {int((wil.top40 == 'yes').sum())} · confirmed {int((wil.confirmed == 'yes').sum())}")
    lines.append("")

    dev = coverage(load_run(a.outputs, "dev", scored), labels[labels.scenario != "wilson"])
    lines.append("=== dev scenarios (7) · per scenario ===")
    summ = dev.groupby("scenario").agg(phases=("phase", "size"), found=("rank", lambda r: int(r.notna().sum())),
                                       in_top40=("top40", lambda t: int((t == "yes").sum())),
                                       confirmed=("confirmed", lambda c: int((c == "yes").sum()))).reset_index()
    lines.append(summ.to_string(index=False))
    tot = summ[["phases", "found", "in_top40", "confirmed"]].sum()
    lines.append(f"total: phases {tot.phases} · found {tot.found} · in top 40 {tot.in_top40} · confirmed {tot.confirmed}")
    lines.append("")
    lines.append("=== dev scenarios · per phase ===")
    lines.append(dev[["scenario", "phase", "incident", "rank", "of", "top40", "confirmed", "p_attack"]].to_string(index=False))

    a.out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:len(lines) - len(dev) - 2]))
    print(f"\nsaved -> {a.out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

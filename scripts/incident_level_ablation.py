#!/usr/bin/env python3
"""Incident-level ablation on the DEV scenarios only: does adding the st_ features change which
hand-off incidents the model keeps?

For each arm (his 35 features, his + st_ 61 features) fit his logistic-regression pipeline
leave-one-scenario-out over the dev scenarios, score every minute out of fold, then give each
dev incident (outputs/incidents.json) the max p_attack over its minutes, exactly as
export_for_model.py attach does. Join label_is_attack from outputs/model_input/incident_features.csv
(evaluation only; never shown in the UI) and count, at the UI threshold p_attack >= 0.5:

    attack incidents kept    = attack-overlapping incidents with p_max >= 0.5
    benign incidents passed  = non-attack incidents with p_max >= 0.5

The holdout (wilson) is never loaded. Writes outputs/ablation/incident_level.txt.
Imports train_supervised.py and ablation_loso.py; it does not modify them.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_supervised as ts  # noqa: E402
from ablation_loso import build_train, load_arms  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
THRESHOLD = 0.5  # same as CONFIRMED_THRESHOLD in src/data/incidents.server.ts
ARMS = ["his", "his+st"]


def oof_scores(arm_data: dict, names: list[str], arm: str, feat_dir: Path) -> dict[str, pd.Series]:
    """Per scenario: minute win_start -> out-of-fold p_attack for this arm."""
    out = {}
    for test in names:
        model = ts.fit_model("logreg", *build_train(arm_data, [n for n in names if n != test], arm))
        arms, L = arm_data[test]
        p = model.predict_proba(arms[arm][0])[:, 1]
        out[test] = pd.Series(p, index=L.win_start.astype(int).values).sort_index()
    return out


def incident_pmax(incidents: list[dict], scores: dict[str, pd.Series]) -> pd.Series:
    vals = {}
    for inc in incidents:
        s = scores.get(inc["scenario"])
        if s is None:
            continue
        s0 = int(pd.Timestamp(inc["start"]).timestamp())
        e0 = int(pd.Timestamp(inc["end"]).timestamp())
        m = s.loc[(s.index >= s0) & (s.index < e0)]
        vals[inc["incident_id"]] = float(m.max()) if len(m) else np.nan
    return pd.Series(vals, name="p_max")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feat-dir", type=Path, default=ROOT / "dataset" / "features")
    ap.add_argument("--st-dir", type=Path, default=ROOT / "outputs" / "model_input")
    ap.add_argument("--incidents", type=Path, default=ROOT / "outputs" / "incidents.json")
    ap.add_argument("--labels-csv", type=Path, default=ROOT / "outputs" / "model_input" / "incident_features.csv")
    ap.add_argument("--out", type=Path, default=ROOT / "outputs" / "ablation" / "incident_level.txt")
    ap.add_argument("--holdout", default="wilson")
    a = ap.parse_args()

    names = [n for n in ts.available(a.feat_dir) if n != a.holdout]  # holdout never loaded
    arm_data = {n: load_arms(a.feat_dir, a.st_dir, n) for n in names}
    incidents = [i for i in json.loads(a.incidents.read_text()) if i["scenario"] in names]
    labels = pd.read_csv(a.labels_csv)
    labels = labels[labels["run"] == "dev"].set_index("incident_id")["label_is_attack"].astype(int)

    lines = [f"Incident-level ablation · dev scenarios {names} · holdout '{a.holdout}' never loaded",
             f"{datetime.now():%Y-%m-%d %H:%M} · threshold p_attack >= {THRESHOLD} · out-of-fold logreg, leave-one-scenario-out",
             f"{len(incidents)} hand-off incidents (top 40 per scenario), {int(labels.reindex([i['incident_id'] for i in incidents]).sum())} overlap an attack phase", ""]
    rows = []
    for arm in ARMS:
        p = incident_pmax(incidents, oof_scores(arm_data, names, arm, a.feat_dir))
        df = pd.DataFrame({"p_max": p, "attack": labels.reindex(p.index)}).dropna()
        kept = df[df.p_max >= THRESHOLD]
        n_attack = int(df.attack.sum())
        n_benign = int((df.attack == 0).sum())
        attack_kept = int(kept.attack.sum())
        benign_passed = int((kept.attack == 0).sum())
        rows.append((arm, attack_kept, n_attack, benign_passed, n_benign, len(kept)))
        lines.append(f"{arm:8s} features={len(arm_data[names[0]][0][arm][1]):2d}  attack incidents kept {attack_kept}/{n_attack}  "
                     f"benign incidents passed {benign_passed}/{n_benign}  total handed to the analyst {len(kept)}")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nsaved -> {a.out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

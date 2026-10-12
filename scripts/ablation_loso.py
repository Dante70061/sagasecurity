#!/usr/bin/env python3
"""Does the stats stage add anything to his model?  Leave-one-scenario-out over the DEV scenarios.

Three arms, same logistic-regression pipeline (his make_model("logreg")), same target (is_burst), same
`usable` mask (quiet-phase minutes dropped from fit and evaluation), same metrics (his evaluate()):
    his       his 35 Z-score features                      dataset/features/<s>_features.csv
    his+st    his 35 + the st_ minute features             outputs/model_input/<s>_stats_features.csv
    st        the st_ features alone
The holdout (wilson) is never loaded. Writes outputs/ablation/{ablation_results,ablation_phase_ranks}.csv.

Run from the repo root, after scripts/build_features.py and scripts/export_for_model.py export:
    python scripts/ablation_loso.py [--frac 0.01]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_supervised as ts  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ARMS = ["his", "his+st", "st"]


def load_arms(feat_dir: Path, st_dir: Path, name: str):
    X_his, L, his_feats = ts.load(feat_dir, name)
    S = pd.read_csv(st_dir / f"{name}_stats_features.csv")
    assert (S.win_start.values == L.win_start.values).all(), f"{name}: st_ grid differs from his grid"
    st_feats = [c for c in S.columns if c not in ts.META]
    X_st = S[st_feats].to_numpy(float)
    assert (X_st >= 0).all(), f"{name}: negative st_ value (log1p would give NaN)"
    return {"his": (X_his, his_feats), "his+st": (np.hstack([X_his, X_st]), his_feats + st_feats),
            "st": (X_st, st_feats)}, L


def build_train(arm_data: dict, names: list[str], arm: str):
    Xs, ys = [], []
    for n in names:
        arms, L = arm_data[n]
        keep = ts.usable(L)
        Xs.append(arms[arm][0][keep])
        ys.append(L.is_burst.values[keep].astype(int))
    return np.vstack(Xs), np.concatenate(ys)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feat-dir", type=Path, default=ROOT / "dataset" / "features")
    ap.add_argument("--st-dir", type=Path, default=ROOT / "outputs" / "model_input")
    ap.add_argument("--labels", type=Path, default=ROOT / "dataset" / "labels.csv")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "outputs" / "ablation")
    ap.add_argument("--holdout", default="wilson")
    ap.add_argument("--frac", type=float, default=0.01, help="alert budget: share of minutes flagged per scenario")
    a = ap.parse_args()

    names = [n for n in ts.available(a.feat_dir) if n != a.holdout]      # holdout never loaded
    arm_data = {n: load_arms(a.feat_dir, a.st_dir, n) for n in names}
    intervals = ts.read_intervals(a.labels)
    n_feats = {arm: len(arm_data[names[0]][0][arm][1]) for arm in ARMS}

    rows, phase_rows = [], []
    for test in names:
        train_names = [n for n in names if n != test]
        arms, L = arm_data[test]
        for arm in ARMS:
            model = ts.fit_model("logreg", *build_train(arm_data, train_names, arm))
            s = model.predict_proba(arms[arm][0])[:, 1]
            r = ts.evaluate(s, L, intervals[test], a.frac)
            rows.append({"test": test, "arm": arm, **{k: v for k, v in r.items() if k != "ranks"}})
            phase_rows += [{"test": test, "arm": arm, "phase": p, "rank": v} for p, v in r["ranks"].items()]
        print(f"fold {test:16s} done", flush=True)

    R, P = pd.DataFrame(rows), pd.DataFrame(phase_rows)
    pd.set_option("display.width", 180)
    print(f"\n=== LEAVE-ONE-SCENARIO-OUT over {len(names)} dev scenarios ('{a.holdout}' never loaded) ===")
    print(f"target = burst-phase minutes (his usable mask); budget = top {a.frac:.0%} of minutes per scenario")
    print("features per arm:", n_feats)
    agg = R.groupby("arm").agg(mean_AP=("AP", "mean"), worst_AP=("AP", "min"), mean_recall=("recall@K", "mean"),
                               phases_caught=("phases_caught", "sum"), of=("n_phases", "sum"),
                               false_pos=("fp@K", "sum")).reindex(ARMS)
    print(agg.round(3).to_string())
    print("\nAP per held-out scenario:")
    print(R.pivot(index="test", columns="arm", values="AP")[ARMS].round(3).to_string())
    print(f"\nrecall@top{a.frac:.0%} per held-out scenario:")
    print(R.pivot(index="test", columns="arm", values="recall@K")[ARMS].round(2).to_string())
    print("\nmedian best-minute rank per phase (lower is better):")
    print(P.pivot_table(index="phase", columns="arm", values="rank", aggfunc="median")[ARMS].round(0).to_string())

    a.out_dir.mkdir(parents=True, exist_ok=True)
    R.to_csv(a.out_dir / "ablation_results.csv", index=False)
    P.to_csv(a.out_dir / "ablation_phase_ranks.csv", index=False)
    print(f"\nsaved -> {a.out_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

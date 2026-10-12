#!/usr/bin/env python3
"""Score every minute with his logistic-regression pipeline. Imports train_supervised.py (never copied).

Model (decided on the dev ablation, scripts/ablation_loso.py): his logreg pipeline, target is_burst, his
`usable` mask, features = his 35 Z-scores + the 26 st_ minute features from export_for_model.py (--arm his+st).

Default: DEV scenarios, out-of-fold. Each dev scenario is scored by a model fitted on the other dev
scenarios, so the scores attached to incidents are honest. Writes dataset/features/<scenario>_scores.csv
with win_start, win_start_utc, p_attack. The holdout (wilson) is never loaded.

--final-holdout: the ONE look at wilson. Fits on all 7 dev scenarios, scores wilson once, writes
dataset/features/wilson_scores.csv and prints AP / recall@top-1% with his evaluate(). Refuses to run
again while that file exists (--force to override; do not change the model after seeing the output).

Run from the repo root, after build_features.py and `export_for_model.py export`:
    python scripts/score_windows.py                     # dev, out-of-fold, his+st
    python scripts/score_windows.py --in-sample         # dev, fitted on all 7 (optimistic)
    python scripts/score_windows.py --final-holdout     # wilson, exactly once
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import train_supervised as ts  # noqa: E402  his module: available / load / usable / fit_model / evaluate
from ablation_loso import ARMS, build_train, load_arms  # noqa: E402  mine: his + st_ feature arms

ROOT = Path(__file__).resolve().parents[1]
SCORE_COL = "p_attack"


def write_scores(feat_dir: Path, out_dir: Path, name: str, p, tag: str) -> None:
    grid = pd.read_csv(feat_dir / f"{name}_features.csv", usecols=list(ts.META))
    path = out_dir / f"{name}_scores.csv"
    grid.assign(**{SCORE_COL: p}).to_csv(path, index=False)
    print(f"{name:16s} {len(grid):6d} minutes, {SCORE_COL} max={p.max():.3f} -> {path}  [{tag}]")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feat-dir", type=Path, default=ROOT / "dataset" / "features")
    ap.add_argument("--st-dir", type=Path, default=ROOT / "outputs" / "model_input")
    ap.add_argument("--out-dir", type=Path, default=None, help="where *_scores.csv go (default: --feat-dir)")
    ap.add_argument("--labels", type=Path, default=ROOT / "dataset" / "labels.csv")
    ap.add_argument("--holdout", default="wilson")
    ap.add_argument("--arm", default="his+st", choices=ARMS)
    ap.add_argument("--model", default="logreg", choices=["logreg", "gbm"])
    ap.add_argument("--frac", type=float, default=0.01, help="alert budget for the holdout printout")
    ap.add_argument("--in-sample", action="store_true", help="dev: fit on all dev scenarios instead of out-of-fold")
    ap.add_argument("--final-holdout", action="store_true", help="fit on all dev scenarios, score the holdout ONCE")
    ap.add_argument("--force", action="store_true", help="re-run the holdout even though its scores exist")
    a = ap.parse_args()
    out_dir = a.out_dir or a.feat_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    names = [n for n in ts.available(a.feat_dir) if n != a.holdout]
    if not names:
        sys.exit(f"no *_features.csv in {a.feat_dir}; run scripts/build_features.py first")
    data = {n: load_arms(a.feat_dir, a.st_dir, n) for n in names}       # holdout not loaded here
    n_feat = len(data[names[0]][0][a.arm][1])

    if a.final_holdout:
        marker = out_dir / f"{a.holdout}_scores.csv"
        if marker.exists() and not a.force:
            raise SystemExit(f"{marker} exists: the holdout has already been scored once. --force to override.")
        X, y = build_train(data, names, a.arm)
        model = ts.fit_model(a.model, X, y)
        arms_h, L_h = load_arms(a.feat_dir, a.st_dir, a.holdout)        # the one and only load of the holdout
        p = model.predict_proba(arms_h[a.arm][0])[:, 1]
        write_scores(a.feat_dir, out_dir, a.holdout, p, f"FINAL {a.arm} {a.model}, {n_feat} features, "
                     f"fitted on {len(names)} dev scenarios / {int(y.sum())} positives")
        r = ts.evaluate(p, L_h, ts.read_intervals(a.labels)[a.holdout], a.frac)
        print(f"\n=== FINAL on '{a.holdout}' ({datetime.now():%Y-%m-%d %H:%M}) ===")
        print(f"AP={r['AP']:.3f}  recall@top{a.frac:.0%} (K={r['K']})={r['recall@K']:.2f}  "
              f"fp@K={r['fp@K']}  phases caught {r['phases_caught']}/{r['n_phases']}  n_pos={r['n_pos']}")
        print("best-minute rank per phase:", r["ranks"])
        return

    if a.in_sample:
        model = ts.fit_model(a.model, *build_train(data, names, a.arm))
    for n in names:
        if not a.in_sample:
            model = ts.fit_model(a.model, *build_train(data, [m for m in names if m != n], a.arm))
        p = model.predict_proba(data[n][0][a.arm][0])[:, 1]
        write_scores(a.feat_dir, out_dir, n, p, f"{'in-sample' if a.in_sample else 'out-of-fold'} {a.arm} {n_feat}f")
    print(f"'{a.holdout}' untouched")


if __name__ == "__main__":
    main()

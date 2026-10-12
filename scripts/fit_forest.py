#!/usr/bin/env python3
"""Fit an Isolation Forest on the per-window Z-score features and rank the windows.

Input : <name>_features.csv from build_features.py
Output: <name>_scores.csv     every window with its anomaly score, rank, flag and top features
        <name>_incidents.csv  flagged windows merged into incidents (this is what the LLM agent receives)
        <name>_forest.joblib  the fitted model

Labels (--labels) are used ONLY for the evaluation printout. The forest never sees them.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score

WINDOW_S = 60
META = ("win_start", "win_start_utc")


def load_intervals(labels_csv: Path, scenario: str):
    with labels_csv.open() as f:
        rows = [r for r in csv.DictReader(f) if r["scenario"] == scenario]
    return sorted(((r["attack"], float(r["start"]), float(r["end"])) for r in rows), key=lambda x: x[1])


def overlaps(starts: np.ndarray, a: float, b: float) -> np.ndarray:
    return (starts < b) & (starts + WINDOW_S > a)


def build_incidents(df: pd.DataFrame, feats: list[str], gap_min: int) -> pd.DataFrame:
    groups, cur = [], None
    for i, t in df.loc[df.flagged, "win_start"].sort_values().items():
        if cur and t - cur["last"] <= gap_min * WINDOW_S:
            cur["last"] = t
            cur["rows"].append(i)
        else:
            cur = {"first": t, "last": t, "rows": [i]}
            groups.append(cur)
    recs = []
    for n, g in enumerate(groups, 1):
        sub = df.loc[g["rows"]]
        top = sub[feats].max().sort_values(ascending=False).head(6)
        recs.append({
            "incident": n, "start_utc": sub.win_start_utc.iloc[0], "end_utc": sub.win_start_utc.iloc[-1],
            "start_ts": g["first"], "end_ts": g["last"] + WINDOW_S, "n_windows": len(sub),
            "max_score": round(sub.score.max(), 4),
            "top_features": "; ".join(f"{k}={v:.1f}" for k, v in top.items() if v > 0)})
    return pd.DataFrame(recs)


def evaluate(df: pd.DataFrame, feats: list[str], iv, fracs) -> None:
    starts = df.win_start.values
    is_attack = np.zeros(len(df), bool)
    for _, a, b in iv:
        is_attack |= overlaps(starts, a, b)
    n_att = int(is_attack.sum())
    print(f"\n== Evaluation: {n_att} attack windows of {len(df)} ({n_att / len(df):.1%}) ==")
    print(f"Average precision (threshold-free): forest {average_precision_score(is_attack, df.score):.3f}"
          f"  | random baseline {n_att / len(df):.3f}")

    base = ((df.get("wz_lvl8", 0) > 0) | (df.get("wz_lvl10", 0) > 0)).values
    print(f"\n{'method':32s} {'flagged':>7s} {'precision':>9s} {'recall':>7s}")
    for f in fracs:
        flag = df["rank"].values <= max(1, round(len(df) * f))
        tp = int((flag & is_attack).sum())
        print(f"{'forest, top ' + format(f, '.0%'):32s} {int(flag.sum()):7d} {tp / flag.sum():9.2f} {tp / n_att:7.2f}")
    tp = int((base & is_attack).sum())
    print(f"{'baseline: any level>=8 alert':32s} {int(base.sum()):7d} {tp / max(1, base.sum()):9.2f} {tp / n_att:7.2f}")

    flag = df.flagged.values
    print(f"\nPer-phase (forest flags top {df.flagged.mean():.1%}; a window can overlap several short phases)")
    print(f"{'phase':22s} {'windows':>7s} {'flagged':>7s} {'caught':>6s} {'best rank':>9s}   baseline")
    for name, a, b in iv:
        m = overlaps(starts, a, b)
        best = int(df.loc[m, "rank"].min())
        print(f"{name:22s} {int(m.sum()):7d} {int((m & flag).sum()):7d} {'yes' if (m & flag).any() else 'NO':>6s} "
              f"{best:9d}   {'yes' if (m & base).any() else 'NO'}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("features", type=Path, help="*_features.csv from build_features.py")
    ap.add_argument("--flag-frac", type=float, default=0.03, help="share of windows to flag (default 3%%)")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--max-samples", type=int, default=1024)
    ap.add_argument("--gap-min", type=int, default=3, help="merge flagged windows at most this many minutes apart")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--labels", type=Path, help="labels.csv, for the evaluation printout only")
    ap.add_argument("--scenario", default="russellmitchell")
    a = ap.parse_args()

    df = pd.read_csv(a.features)
    feats = [c for c in df.columns if c not in META]
    X = df[feats].to_numpy()
    model = IsolationForest(n_estimators=a.trees, max_samples=min(a.max_samples, len(X)),
                            contamination="auto", random_state=a.seed, n_jobs=-1).fit(X)

    df["score"] = -model.score_samples(X)                      # higher = more anomalous
    df["rank"] = df.score.rank(ascending=False, method="first").astype(int)
    df["flagged"] = df["rank"] <= max(1, round(len(df) * a.flag_frac))
    order = np.argsort(-X, axis=1)[:, :3]
    df["top_features"] = [", ".join(f"{feats[j]}={X[i, j]:.1f}" for j in row if X[i, j] > 0)
                          for i, row in enumerate(order)]

    stem = a.features.with_name(a.features.stem.replace("_features", ""))
    df[[*META, "score", "rank", "flagged", "top_features"]].to_csv(f"{stem}_scores.csv", index=False)
    inc = build_incidents(df, feats, a.gap_min)
    inc.to_csv(f"{stem}_incidents.csv", index=False)
    joblib.dump({"model": model, "features": feats}, f"{stem}_forest.joblib")
    print(f"fitted on {len(df)} windows x {len(feats)} features; flagged {int(df.flagged.sum())} windows "
          f"-> {len(inc)} incidents")

    if a.labels:
        evaluate(df, feats, load_intervals(a.labels, a.scenario), (0.01, a.flag_frac, 0.05))


if __name__ == "__main__":
    main()

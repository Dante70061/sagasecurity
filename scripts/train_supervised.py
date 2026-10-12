#!/usr/bin/env python3
"""Compare window scorers by leave-one-scenario-out CV, then run ONE final test on a held-out scenario.

  cv    leave-one-scenario-out over every scenario EXCEPT the holdout. The holdout is never loaded.
  final fit on all non-holdout scenarios, score the holdout once. Refuses to run twice (see --force).

Target ("burst" positives): windows overlapping a loud phase (service_scans, dirb, wpscan, webshell,
reverse_shell, privilege_escalation). Windows that overlap ONLY the quiet phases (network_scans, cracking,
dnsteal, service_stop) are ambiguous - the alerts barely show them - so they are dropped from training
and from evaluation instead of being called benign or attack.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer

BURST = {"service_scans", "dirb", "wpscan", "webshell", "reverse_shell", "privilege_escalation"}
META = ("win_start", "win_start_utc")
MODELS = ("sum_z", "iforest", "logreg", "gbm")


def available(feat_dir: Path) -> list[str]:
    return sorted(p.name[: -len("_features.csv")] for p in feat_dir.glob("*_features.csv"))


def load(feat_dir: Path, name: str):
    X = pd.read_csv(feat_dir / f"{name}_features.csv")
    L = pd.read_csv(feat_dir / f"{name}_labels.csv")
    assert (X.win_start.values == L.win_start.values).all(), f"{name}: features/labels misaligned"
    feats = [c for c in X.columns if c not in META]
    return X[feats].to_numpy(float), L, feats


def read_intervals(labels_csv: Path):
    out: dict[str, list] = {}
    with labels_csv.open() as f:
        for r in csv.DictReader(f):
            out.setdefault(r["scenario"], []).append((r["attack"], float(r["start"]), float(r["end"])))
    return out


def usable(L: pd.DataFrame) -> np.ndarray:
    """Drop windows that overlap only quiet phases."""
    return ~((L.is_attack & ~L.is_burst).values)


def build_train(data: dict, names: list[str]):
    Xs, ys = [], []
    for n in names:
        X, L, _ = data[n]
        keep = usable(L)
        Xs.append(X[keep])
        ys.append(L.is_burst.values[keep].astype(int))
    return np.vstack(Xs), np.concatenate(ys)


def make_model(kind: str):
    if kind == "logreg":
        return make_pipeline(FunctionTransformer(np.log1p),
                             LogisticRegression(C=0.1, class_weight="balanced", max_iter=2000))
    if kind == "gbm":
        return HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=150,
                                              min_samples_leaf=20, l2_regularization=1.0,
                                              early_stopping=False, random_state=0)
    raise ValueError(kind)


def fit_model(kind: str, X: np.ndarray, y: np.ndarray):
    m = make_model(kind)
    if kind == "gbm":
        m.fit(X, y, sample_weight=np.where(y == 1, (y == 0).sum() / max(1, y.sum()), 1.0))
    else:
        m.fit(X, y)
    return m


def score(kind: str, X_te: np.ndarray, train=None, model=None) -> np.ndarray:
    if kind == "sum_z":
        return X_te.sum(axis=1)
    if kind == "iforest":                       # unsupervised: fit on the scenario being scored
        f = IsolationForest(n_estimators=300, max_samples=min(1024, len(X_te)), random_state=0, n_jobs=-1)
        return -f.fit(X_te).score_samples(X_te)
    model = model or fit_model(kind, *train)
    return model.predict_proba(X_te)[:, 1]


def evaluate(s: np.ndarray, L: pd.DataFrame, intervals, frac: float) -> dict:
    ev = usable(L)
    y, s, starts = L.is_burst.values[ev].astype(int), s[ev], L.win_start.values[ev]
    win_s = int(L.win_start.diff().dropna().mode().iloc[0])
    K = max(1, int(np.ceil(frac * len(L))))
    order = np.argsort(-s, kind="stable")
    top = np.zeros(len(s), bool)
    top[order[:K]] = True
    rank = np.empty(len(s), int)
    rank[order] = np.arange(1, len(s) + 1)
    ranks = {}
    for name, a, b in intervals:
        if name in BURST:
            m = (starts < b) & (starts + win_s > a)
            if m.any():
                ranks[name] = (int(rank[m].min()), bool(top[m].any()))
    return {"AP": average_precision_score(y, s), "recall@K": (top & (y == 1)).sum() / y.sum(), "K": K,
            "fp@K": int(K - (top & (y == 1)).sum()), "phases_caught": sum(c for _, c in ranks.values()), "n_phases": len(ranks),
            "ranks": {k: r for k, (r, _) in ranks.items()}, "n_pos": int(y.sum())}


def cmd_cv(a, data, names, intervals):
    rows, phase_rows = [], []
    for test in names:
        train = build_train(data, [n for n in names if n != test])
        X, L, _ = data[test]
        for kind in MODELS:
            r = evaluate(score(kind, X, train=train), L, intervals[test], a.frac)
            rows.append({"test": test, "model": kind, **{k: v for k, v in r.items() if k != "ranks"}})
            phase_rows += [{"test": test, "model": kind, "phase": p, "rank": v} for p, v in r["ranks"].items()]
        print(f"fold {test:16s} done", flush=True)
    R, P = pd.DataFrame(rows), pd.DataFrame(phase_rows)
    pd.set_option("display.width", 160)
    print(f"\n=== LEAVE-ONE-SCENARIO-OUT over {len(names)} scenarios (holdout '{a.holdout}' untouched) ===")
    print("positives = burst-phase windows; flagged = top", f"{a.frac:.0%}", "of windows per scenario")
    agg = R.groupby("model").agg(mean_AP=("AP", "mean"), worst_AP=("AP", "min"), mean_recall=("recall@K", "mean"),
                                 phases_caught=("phases_caught", "sum"), of=("n_phases", "sum"),
                                 false_pos=("fp@K", "sum")).reindex(MODELS)
    print(agg.round(3).to_string())
    print("\nAP per held-out scenario:")
    print(R.pivot(index="test", columns="model", values="AP")[list(MODELS)].round(3).to_string())
    print("\nmedian best-window rank per phase (lower is better):")
    print(P.pivot_table(index="phase", columns="model", values="rank", aggfunc="median")[list(MODELS)].round(0).to_string())
    out = a.out_dir
    out.mkdir(parents=True, exist_ok=True)
    R.to_csv(out / "cv_results.csv", index=False)
    P.to_csv(out / "cv_phase_ranks.csv", index=False)
    print(f"\nsaved -> {out}")


def cmd_final(a, data, names, intervals):
    marker = a.out_dir / "final_eval.done"
    if marker.exists() and not a.force:
        raise SystemExit(f"Final test already run ({marker.read_text().strip()}). The holdout is spent; use --force to override.")
    if a.model not in MODELS:
        raise SystemExit(f"--model must be one of {MODELS}")
    a.out_dir.mkdir(parents=True, exist_ok=True)
    X, L, feats = load(a.feat_dir, a.holdout)
    train = build_train(data, names)
    model = fit_model(a.model, *train) if a.model in ("logreg", "gbm") else None
    print(f"=== FINAL TEST on '{a.holdout}' | trained on {len(names)} scenarios, {int(train[1].sum())} positives ===")
    rows = []
    for kind in dict.fromkeys(["sum_z", "iforest", a.model]):
        r = evaluate(score(kind, X, train=train, model=model if kind == a.model else None), L, intervals[a.holdout], a.frac)
        rows.append({"model": kind, **{k: v for k, v in r.items() if k != "ranks"}, "phase_ranks": r["ranks"]})
        print(f"{kind:8s} AP={r['AP']:.3f} recall@{r['K']}={r['recall@K']:.2f} "
              f"phases caught {r['phases_caught']}/{r['n_phases']}  ranks={r['ranks']}")
    pd.DataFrame(rows).to_csv(a.out_dir / "final_results.csv", index=False)
    if model is not None:
        joblib.dump({"model": model, "features": feats, "kind": a.model}, a.out_dir / f"{a.model}_final.joblib")
    marker.write_text(f"{datetime.now():%Y-%m-%d %H:%M} model={a.model}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["cv", "final"])
    ap.add_argument("--feat-dir", type=Path, default=Path("dataset/features"))
    ap.add_argument("--labels", type=Path, default=Path("dataset/labels.csv"))
    ap.add_argument("--out-dir", type=Path, default=Path("dataset/models"))
    ap.add_argument("--holdout", default="wilson")
    ap.add_argument("--frac", type=float, default=0.01, help="share of windows flagged per scenario")
    ap.add_argument("--model", default="gbm", help="model to test in 'final' mode")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    names = [n for n in available(a.feat_dir) if n != a.holdout]          # holdout is never loaded in cv
    data = {n: load(a.feat_dir, n) for n in names}
    intervals = read_intervals(a.labels)
    {"cv": cmd_cv, "final": cmd_final}[a.mode](a, data, names, intervals)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Turn the merged alert stream into per-window feature rows for an Isolation Forest.

Input : merged JSONL from merge_alerts.py (one alert per line)
Output: one row per 1-minute window (network-wide), every feature stored as a
        Z-score with negative values clipped to 0.

Pipeline: filter -> window -> raw features -> log1p -> Z-score -> clip at 0
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

WINDOW_S = 60
CORR_RULES = {"20100", "20151", "20152", "20162"}   # Wazuh IDS correlation rules
AUTH_FAIL_RULES = {"2501", "5503", "9705", "9751", "5706"}
PRIV_RULES = {"5402", "5304"}                       # sudo to root, UID change
DROP_FASTLOG_RULES = {"20101"}                      # fast.log copy of eve.json events
RARE_FRAC = 0.001                                   # rule seen in < 0.1% of a source's alerts
BURST_LOOKBACK = 60                                 # windows, for the trailing-median burst features


def load(path: Path) -> pd.DataFrame:
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            ex = r.get("extras") or {}
            dst = r.get("dst_ip")
            rows.append({
                "ts": float(r["ts"]), "source": r["source"], "host": r.get("host"),
                "location": r.get("location") or "", "detector": r.get("detector") or "",
                "rule_id": str(r.get("detector_id")), "src_ip": r.get("src_ip"),
                "dst_ip": dst.split(":")[0] if dst else None,       # strip stray ":port"
                "http_path": r.get("http_path"), "status": r.get("status"), "ua": r.get("ua"),
                "is_baseline": bool(r.get("is_baseline")),
                "level": ex.get("rule_level"), "signature": ex.get("signature"),
                "dst_port": ex.get("dst_port"), "training": bool(ex.get("training_mode")),
            })
    return pd.DataFrame(rows)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    n0 = len(df)
    df = df[~((df.source == "aminer") & df.training)]                      # detector still learning
    dup_fast = (df.source == "wazuh") & df.location.str.contains("fast.log") \
        & df.rule_id.isin(DROP_FASTLOG_RULES)
    df = df[~dup_fast]
    print(f"cleaned {n0} -> {len(df)} alerts")
    return df.reset_index(drop=True)


def add_rarity(df: pd.DataFrame) -> pd.DataFrame:
    """Per-alert rarity = log(N_source / count of its rule/signature) within its own source."""
    df = df.copy()
    df["key"] = np.where(df.signature.notna(), df.signature, df.detector)
    cnt = df.groupby(["source", "key"])["ts"].transform("size")
    tot = df.groupby("source")["ts"].transform("size")
    df["rarity"] = np.log(tot / cnt)
    df["is_rare"] = (cnt / tot) < RARE_FRAC
    return df


def raw_features(df: pd.DataFrame) -> pd.DataFrame:
    """One row per WINDOW_S window (including empty ones) of non-negative counts/measures."""
    df = df.copy()
    df["win"] = (df.ts // WINDOW_S).astype(np.int64)
    idx = pd.RangeIndex(df.win.min(), df.win.max() + 1, name="win")
    wz, am = df[df.source == "wazuh"], df[df.source == "aminer"]
    F = pd.DataFrame(index=idx)

    def cnt(sub, name):
        F[name] = sub.groupby("win").size().reindex(idx, fill_value=0)

    def nun(sub, col, name):
        F[name] = sub.groupby("win")[col].nunique().reindex(idx, fill_value=0)

    # ---- Wazuh: volume and severity
    lvl = wz.level.astype(float)
    cnt(wz, "wz_n")
    cnt(wz[~wz.is_baseline], "wz_nonbaseline")        # excludes routine Dovecot-success / ClamAV
    cnt(wz[lvl >= 6], "wz_lvl6")
    cnt(wz[lvl >= 8], "wz_lvl8")
    cnt(wz[lvl >= 10], "wz_lvl10")
    F["wz_max_lvl"] = lvl.groupby(wz.win).max().reindex(idx, fill_value=0)

    # ---- Wazuh: diversity and concentration
    nun(wz, "detector", "wz_rules")
    nun(wz, "src_ip", "wz_src_ips")
    nun(wz, "dst_port", "wz_dst_ports")
    nun(wz, "host", "wz_hosts")
    per_src = wz.dropna(subset=["src_ip"]).groupby(["win", "src_ip"]).size()
    F["wz_max_per_src"] = per_src.groupby(level=0).max().reindex(idx, fill_value=0)
    g = wz.groupby(["win", "key"]).size()
    p = g / g.groupby(level=0).transform("sum")
    F["wz_rule_entropy"] = (-(p * np.log(p))).groupby(level=0).sum().reindex(idx, fill_value=0)

    # ---- Wazuh: rarity and security-relevant rule families
    cnt(wz[wz.is_rare], "wz_rare_n")
    F["wz_max_rarity"] = wz.groupby("win").rarity.max().reindex(idx, fill_value=0)
    cnt(wz[wz.rule_id.isin(CORR_RULES)], "wz_corr_n")
    cnt(wz[wz.rule_id == "20100"], "wz_first_time")
    cnt(wz[wz.rule_id.isin(AUTH_FAIL_RULES)], "wz_auth_fail")
    cnt(wz[wz.rule_id.isin(PRIV_RULES)], "wz_priv")
    cnt(wz[wz.location.str.contains("audit.log")], "wz_audit")
    cnt(wz[wz.signature.fillna("").str.contains("SCAN")], "wz_scan_sig")
    cnt(wz[wz.location.str.contains("suricata/eve")], "wz_ids")

    # ---- Web activity seen by Wazuh
    web = wz[wz.http_path.notna()]
    cnt(web, "web_n")
    cnt(web[web.status.fillna("").str[:1].isin(["4", "5"])], "web_err")
    nun(web, "http_path", "web_paths")
    nun(web, "ua", "web_uas")

    # ---- AMiner
    cnt(am, "am_n")
    nun(am, "detector", "am_detectors")
    cnt(am[am.detector.str.contains("DNS")], "am_dns")
    cnt(am[am.detector.str.contains("Apache")], "am_web")
    cnt(am[am.detector.str.contains("Audit")], "am_audit")
    cnt(am[am.detector.str.contains("CPU")], "am_cpu")
    cnt(am[am.is_rare], "am_rare_n")
    F["am_max_rarity"] = am.groupby("win").rarity.max().reindex(idx, fill_value=0)
    return F.astype(float)


def add_bursts(L: pd.DataFrame) -> pd.DataFrame:
    """Window volume minus its trailing median (computed on log1p values)."""
    for c in ("wz_n", "am_n"):
        base = L[c].shift(1).rolling(BURST_LOOKBACK, min_periods=1).median()
        L[c + "_burst"] = (L[c] - base).fillna(0.0)
    return L


def zscore(L: pd.DataFrame, stats: dict | None = None):
    """Z-score each column, then clip negatives to 0. Constant columns become 0."""
    if stats is None:
        stats = {c: [float(L[c].mean()), float(L[c].std(ddof=0))] for c in L}
    Z = pd.DataFrame(index=L.index)
    for c in L:
        mean, std = stats[c]
        Z[c] = 0.0 if std == 0 else (L[c] - mean) / std
    return Z.clip(lower=0.0), stats


def window_labels(win_idx, labels_csv: Path, scenario: str) -> pd.DataFrame:
    """EVALUATION ONLY. Phase with the largest overlap per window, else 'benign'."""
    with labels_csv.open() as f:
        iv = [(r["attack"], float(r["start"]), float(r["end"]))
              for r in csv.DictReader(f) if r["scenario"] == scenario]
    out = []
    for w in win_idx:
        s, e = w * WINDOW_S, (w + 1) * WINDOW_S
        best, ov = "benign", 0.0
        for name, a, b in iv:
            o = min(e, b) - max(s, a)
            if o > ov:
                best, ov = name, o
        out.append((w * WINDOW_S, best, best != "benign"))
    return pd.DataFrame(out, columns=["win_start", "phase", "is_attack"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("merged", type=Path, help="merged JSONL from merge_alerts.py")
    ap.add_argument("-o", "--output", type=Path, help="features CSV (default: <merged>_features.csv)")
    ap.add_argument("--stats-in", type=Path, help="reuse mean/std from another scenario instead of fitting")
    ap.add_argument("--raw-out", type=Path, help="also save the un-normalised (log1p) features")
    ap.add_argument("--labels", type=Path, help="labels.csv; writes a separate *_labels.csv for evaluation")
    ap.add_argument("--scenario", default="russellmitchell")
    a = ap.parse_args()

    out = a.output or a.merged.with_name(a.merged.stem + "_features.csv")
    df = add_rarity(clean(load(a.merged)))
    L = add_bursts(np.log1p(raw_features(df)))
    stats = json.loads(a.stats_in.read_text()) if a.stats_in else None
    Z, stats = zscore(L, stats)

    Z.insert(0, "win_start", Z.index.values * WINDOW_S)
    Z.insert(1, "win_start_utc", [datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M")
                                  for t in Z.win_start])
    Z.to_csv(out, index=False)
    out.with_suffix(".stats.json").write_text(json.dumps(stats, indent=1))
    if a.raw_out:
        L.to_csv(a.raw_out)
    feats = [c for c in Z.columns if c not in ("win_start", "win_start_utc")]
    print(f"wrote {len(Z)} windows x {len(feats)} features -> {out}")

    score = Z[feats].sum(axis=1)
    top = Z.assign(score=score).nlargest(10, "score")[["win_start_utc", "score"]]
    if a.labels:
        lab = window_labels(Z.index, a.labels, a.scenario)
        lab.to_csv(out.with_name(out.stem.replace("_features", "") + "_labels.csv"), index=False)
        top["phase"] = lab.set_index(lab.win_start).phase.reindex(Z.loc[top.index, "win_start"]).values
        print(f"attack windows: {int(lab.is_attack.sum())} of {len(lab)}")
    print("top 10 windows by summed Z:\n", top.to_string())


if __name__ == "__main__":
    main()

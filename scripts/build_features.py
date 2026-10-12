#!/usr/bin/env python3
"""Turn the merged alert stream into per-window feature rows, one feature file per scenario.

Input : merged JSONL from merge_alerts.py (all scenarios; each row has a `scenario` field)
Output: <out-dir>/<scenario>_features.csv  one row per window, every feature a Z-score (negatives clipped to 0)
        <out-dir>/<scenario>_features.stats.json  the mean/std used, so another scenario can be scored with them
        <out-dir>/<scenario>_labels.csv  (only with --labels) EVALUATION/TRAINING TARGETS, never model input

Each scenario is normalised against ITSELF: a Z-score means "unusual for this network".
Pipeline per scenario: filter -> window -> raw features -> log1p -> Z-score -> clip at 0
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

DEFAULT_WINDOW_S = 60
CORR_RULES = {"20100", "20151", "20152", "20162"}   # Wazuh IDS correlation rules
AUTH_FAIL_RULES = {"2501", "5503", "9705", "9751", "5706"}
PRIV_RULES = {"5402", "5304"}                       # sudo to root, UID change
DROP_FASTLOG_RULES = {"20101"}                      # fast.log copy of eve.json events
RARE_FRAC = 0.001                                   # rule seen in < 0.1% of a source's alerts
BURST_LOOKBACK = 60                                 # windows, for the trailing-median burst features
BURST_PHASES = {"service_scans", "dirb", "wpscan", "webshell", "reverse_shell", "privilege_escalation"}


def flatten(r: dict) -> dict:
    ex = r.get("extras") or {}
    dst = r.get("dst_ip")
    return {
        "ts": float(r["ts"]), "source": r["source"], "host": r.get("host"),
        "location": r.get("location") or "", "detector": r.get("detector") or "",
        "rule_id": str(r.get("detector_id")), "src_ip": r.get("src_ip"),
        "dst_ip": dst.split(":")[0] if dst else None,           # strip stray ":port"
        "http_path": r.get("http_path"), "status": r.get("status"), "ua": r.get("ua"),
        "is_baseline": bool(r.get("is_baseline")),
        "level": ex.get("rule_level"), "signature": ex.get("signature"),
        "dst_port": ex.get("dst_port"), "training": bool(ex.get("training_mode")),
    }


def iter_scenarios(path: Path, default_scenario: str, only: set[str] | None) -> Iterator[tuple[str, pd.DataFrame]]:
    """Stream the merged file and yield one DataFrame per scenario (the file is written scenario by scenario)."""
    cur, rows, seen = None, [], set()
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            s = r.get("scenario") or default_scenario
            if s != cur:
                if rows:
                    yield cur, pd.DataFrame(rows)
                if s in seen:
                    raise SystemExit(f"scenario {s!r} appears in more than one block of {path}")
                cur, rows = s, []
                seen.add(s)
            if only is None or s in only:
                rows.append(flatten(r))
    if rows:
        yield cur, pd.DataFrame(rows)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df[~((df.source == "aminer") & df.training)]                      # detector still learning
    dup_fast = (df.source == "wazuh") & df.location.str.contains("fast.log") \
        & df.rule_id.isin(DROP_FASTLOG_RULES)
    return df[~dup_fast].reset_index(drop=True)


def add_rarity(df: pd.DataFrame) -> pd.DataFrame:
    """Per-alert rarity = log(N_source / count of its rule/signature) within its own source."""
    df = df.copy()
    df["key"] = np.where(df.signature.notna(), df.signature, df.detector)
    cnt = df.groupby(["source", "key"])["ts"].transform("size")
    tot = df.groupby("source")["ts"].transform("size")
    df["rarity"] = np.log(tot / cnt)
    df["is_rare"] = (cnt / tot) < RARE_FRAC
    return df


def raw_features(df: pd.DataFrame, window_s: int) -> pd.DataFrame:
    """One row per window (including empty ones) of non-negative counts/measures."""
    df = df.copy()
    df["win"] = (df.ts // window_s).astype(np.int64)
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


def read_intervals(labels_csv: Path) -> dict[str, list[tuple[str, float, float]]]:
    out: dict[str, list] = {}
    with labels_csv.open() as f:
        for r in csv.DictReader(f):
            out.setdefault(r["scenario"], []).append((r["attack"], float(r["start"]), float(r["end"])))
    return out


def window_labels(win_idx, intervals, window_s: int) -> pd.DataFrame:
    """TARGETS ONLY. phase = largest overlap ('benign' if none); is_attack = overlaps any phase;
    is_burst = overlaps a loud burst phase (the ones the alerts can actually show)."""
    rows = []
    for w in win_idx:
        s, e = w * window_s, (w + 1) * window_s
        best, ov, any_att, any_burst = "benign", 0.0, False, False
        for name, a, b in intervals:
            o = min(e, b) - max(s, a)
            if o > 0:
                any_att = True
                any_burst |= name in BURST_PHASES
                if o > ov:
                    best, ov = name, o
        rows.append((s, best, any_att, any_burst))
    return pd.DataFrame(rows, columns=["win_start", "phase", "is_attack", "is_burst"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("merged", type=Path, help="merged JSONL from merge_alerts.py")
    ap.add_argument("-o", "--out-dir", type=Path, help="default: <merged dir>/features")
    ap.add_argument("--scenarios", help="comma-separated subset, e.g. shaw,santos (default: all)")
    ap.add_argument("--window-s", type=int, default=DEFAULT_WINDOW_S, help="window length in seconds")
    ap.add_argument("--labels", type=Path, help="labels.csv; also writes <scenario>_labels.csv")
    ap.add_argument("--stats-in", type=Path, help="reuse mean/std from another scenario (single-scenario runs)")
    ap.add_argument("--default-scenario", default="russellmitchell",
                    help="name to use for old merged files that have no `scenario` field")
    a = ap.parse_args()

    out_dir = a.out_dir or a.merged.parent / "features"
    out_dir.mkdir(parents=True, exist_ok=True)
    only = set(a.scenarios.split(",")) if a.scenarios else None
    intervals = read_intervals(a.labels) if a.labels else {}
    stats_in = json.loads(a.stats_in.read_text()) if a.stats_in else None

    summary = []
    for scenario, raw in iter_scenarios(a.merged, a.default_scenario, only):
        df = add_rarity(clean(raw))
        L = add_bursts(np.log1p(raw_features(df, a.window_s)))
        Z, stats = zscore(L, stats_in)
        Z.insert(0, "win_start", Z.index.values * a.window_s)
        Z.insert(1, "win_start_utc", [datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                                      for t in Z.win_start])
        Z.to_csv(out_dir / f"{scenario}_features.csv", index=False)
        (out_dir / f"{scenario}_features.stats.json").write_text(json.dumps(stats, indent=1))

        row = {"scenario": scenario, "raw": len(raw), "kept": len(df), "windows": len(Z)}
        if a.labels:
            if scenario in intervals:
                lab = window_labels(Z.index, intervals[scenario], a.window_s)
                lab.to_csv(out_dir / f"{scenario}_labels.csv", index=False)
                row.update(attack=int(lab.is_attack.sum()), burst=int(lab.is_burst.sum()))
            else:
                print(f"warning: no rows for {scenario!r} in {a.labels}")
        summary.append(row)
        print(row, flush=True)

    s = pd.DataFrame(summary)
    print(f"\nwrote {len(s)} scenarios x {Z.shape[1] - 2} features, window={a.window_s}s -> {out_dir}")
    print(s.to_string(index=False))
    if "burst" in s:
        print(f"\ntotal burst-phase windows (the realistic positives): {int(s.burst.sum())} "
              f"| all attack windows: {int(s.attack.sum())} | all windows: {int(s.windows.sum())}")


if __name__ == "__main__":
    main()

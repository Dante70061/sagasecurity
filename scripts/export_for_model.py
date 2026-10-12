#!/usr/bin/env python3
"""Adapter between the stats stage and the model stage.

  export   outputs/windows_z.parquet (+ outputs/wilson_test/) -> outputs/model_input/<scenario>_stats_features.csv
           one row per minute on the SAME win_start grid as dataset/features/<scenario>_features.csv
           (left join onto his grid, zero fill), every value clipped at 0 so the model's log1p never sees < -1.
           Also writes outputs/model_input/incident_features.csv: one row per incident, label_* columns
           are evaluation-only and must never be model input.
  attach   dataset/features/<scenario>_scores.csv (win_start + p_attack) -> outputs/incidents_scored.json
           each incident gets the max / mean model probability over its minutes.

Run from the repo root:
    python scripts/export_for_model.py export
    python scripts/export_for_model.py attach [--score-col p_attack]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DEV_SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler"]
HOLDOUT = "wilson"
WINDOW_S = 60
FLAG_Z = 4.0                      # same incident threshold as stats_pipeline.FLAG_Z
BURST = {"service_scans", "dirb", "wpscan", "webshell", "reverse_shell", "privilege_escalation"}
META = ["win_start", "win_start_utc"]


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def utc(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ----------------------------------------------------------------------------- export: minutes
def minute_features(agg: pd.DataFrame) -> pd.DataFrame:
    """Collapse (scenario, entity, window) z-scores to one row per (scenario, window).

    max over entities for every z column and z_max; a few counts describing how many hosts are involved.
    """
    z_cols = [c for c in agg.columns if c.endswith("_z")]
    by = agg.groupby(level=["scenario", "window"])
    out = by[z_cols].max().rename(columns=lambda c: f"st_{c}")
    out["st_z_max"] = by["z_max"].max()
    out["st_n_flagged"] = (agg["z_max"] >= FLAG_Z).groupby(level=["scenario", "window"]).sum()
    out["st_n_active"] = (agg["total"] > 0).groupby(level=["scenario", "window"]).sum()
    out["st_total_alerts"] = by["total"].sum()
    out["st_max_level"] = by["max_level"].max()
    out = out.clip(lower=0.0).astype(float)            # the model applies log1p to every column
    out = out.reset_index()
    out["win_start"] = (out["window"].astype("int64") // 10**9).astype(int)
    return out.drop(columns=["window"])


def his_grid(feat_dir: Path, scenario: str) -> pd.DataFrame | None:
    p = feat_dir / f"{scenario}_features.csv"
    if not p.exists():
        return None
    g = pd.read_csv(p, usecols=META)
    g["win_start"] = g["win_start"].astype(int)
    return g


def export_minutes(parquets: list[Path], feat_dir: Path, out_dir: Path) -> list[str]:
    written = []
    for pq in parquets:
        if not pq.exists():
            print(f"skip: {pq} not found")
            continue
        agg = pd.read_parquet(pq)
        mins = minute_features(agg)
        for scen, m in mins.groupby("scenario"):
            m = m.drop(columns=["scenario"])
            grid = his_grid(feat_dir, scen)
            if grid is None:
                print(f"warning: {feat_dir}/{scen}_features.csv missing; using the stats-stage minute grid instead")
                grid = pd.DataFrame({"win_start": m["win_start"]})
                grid["win_start_utc"] = grid["win_start"].map(utc)
            extra = set(m["win_start"]) - set(grid["win_start"])
            if extra:
                print(f"warning: {scen}: {len(extra)} stats minutes outside his grid were dropped")
            joined = grid.merge(m, on="win_start", how="left")
            st_cols = [c for c in joined.columns if c.startswith("st_")]
            joined[st_cols] = joined[st_cols].fillna(0.0)
            assert (joined[st_cols] >= 0).all().all(), f"{scen}: negative value after clipping"
            assert joined["win_start"].is_monotonic_increasing and joined["win_start"].is_unique
            p = out_dir / f"{scen}_stats_features.csv"
            joined[META + st_cols].to_csv(p, index=False)
            print(f"{scen:16s} {len(joined):6d} minutes x {len(st_cols)} st_ features -> {rel(p)}")
            written.append(scen)
    return written


# ----------------------------------------------------------------------------- export: incidents
def run_name(run_dir: Path) -> str:
    """outputs/ -> 'dev', outputs/wilson_test -> 'wilson_test'. Incident ids restart at INC-0001 in each run,
    so (run, incident_id) is the unique key, never incident_id alone."""
    return "dev" if run_dir.resolve() == (ROOT / "outputs").resolve() else run_dir.name


def incident_rows(inc_json: Path, eval_csv: Path) -> pd.DataFrame:
    incidents = json.loads(inc_json.read_text())
    ev = pd.read_csv(eval_csv).set_index("incident_id") if eval_csv.exists() else None
    rows = []
    for inc in incidents:
        r = {"run": run_name(inc_json.parent), "incident_id": inc["incident_id"], "scenario": inc["scenario"], "kind": inc["kind"],
             "entity": inc["entity"], "start": inc["start"], "end": inc["end"],
             "start_ts": int(pd.Timestamp(inc["start"]).timestamp()),
             "end_ts": int(pd.Timestamp(inc["end"]).timestamp()),
             "n_windows": inc["n_windows"], "n_alerts": inc["n_alerts"], "n_tools": len(inc["tools"]),
             "peak_z": max(0.0, float(inc["peak_z"])), "n_reasons": len(inc["reasons"]),
             "n_targets": len(inc["targets"] or [])}
        for reason in inc["reasons"]:
            r[f"{reason['feature']}_peak"] = max(0.0, float(reason["z"]))
        if ev is not None and inc["incident_id"] in ev.index:
            e = ev.loc[inc["incident_id"]]
            phases = [p for p in str(e["phases"]).split(",") if p and p != "nan"]
            r["label_phases"] = ",".join(phases)
            r["label_is_attack"] = int(bool(phases))
            r["label_is_burst"] = int(bool(set(phases) & BURST))
            r["label_rank_in_scenario"] = int(e["rank_in_scenario"])
        rows.append(r)
    df = pd.DataFrame(rows)
    peak_cols = sorted(c for c in df.columns if c.endswith("_peak"))
    df[peak_cols] = df[peak_cols].fillna(0.0).clip(lower=0.0)
    front = ["run", "incident_id", "scenario", "kind", "entity", "start", "end", "start_ts", "end_ts",
             "n_windows", "n_alerts", "n_tools", "n_targets", "peak_z", "n_reasons"]
    label = [c for c in df.columns if c.startswith("label_")]
    return df[front + peak_cols + label]


def scenario_summary(parquets: list[Path]) -> dict:
    """Per-scenario funnel numbers for the dashboard: alerts analysed (after dedup and baseline filter),
    minutes, hosts, time span. No labels."""
    out = {}
    for pq in parquets:
        if not pq.exists():
            continue
        agg = pd.read_parquet(pq)
        idx = agg.index.to_frame(index=False)
        for scen, g in agg.groupby(level="scenario"):
            w = idx.loc[idx.scenario == scen, "window"]
            out[scen] = {"run": run_name(pq.parent), "alerts": int(g["total"].sum()),
                         "minutes": int(w.nunique()), "hosts": int(idx.loc[idx.scenario == scen, "entity"].nunique()),
                         "start": w.min().isoformat(), "end": (w.max() + pd.Timedelta(seconds=WINDOW_S)).isoformat()}
    return out


def cmd_export(a) -> None:
    a.out_dir.mkdir(parents=True, exist_ok=True)
    runs = [a.outputs, a.outputs / "wilson_test"]
    export_minutes([r / "windows_z.parquet" for r in runs], a.feat_dir, a.out_dir)
    summ = scenario_summary([r / "windows_z.parquet" for r in runs])
    (a.out_dir / "scenario_summary.json").write_text(json.dumps(summ, indent=1))
    print(f"{len(summ)} scenarios -> {rel(a.out_dir / 'scenario_summary.json')}")
    parts = [incident_rows(r / "incidents.json", r / "incidents_eval.csv")
             for r in runs if (r / "incidents.json").exists()]
    inc = pd.concat(parts, ignore_index=True)
    p = a.out_dir / "incident_features.csv"
    inc.to_csv(p, index=False)
    print(f"{len(inc)} incidents -> {rel(p)}  (label_* columns are evaluation-only)")


# ----------------------------------------------------------------------------- attach
def cmd_attach(a) -> None:
    scores = {}
    for p in sorted(a.scores_dir.glob("*_scores.csv")):
        scen = p.name[: -len("_scores.csv")]
        s = pd.read_csv(p)
        if a.score_col not in s.columns:
            sys.exit(f"{p}: no column {a.score_col!r}; columns are {list(s.columns)}")
        scores[scen] = s.set_index(s["win_start"].astype(int))[a.score_col].sort_index()
    if not scores:
        sys.exit(f"no *_scores.csv in {a.scores_dir}; run scripts/score_windows.py first")

    out, n_scored, missing = [], 0, set()
    for run in [a.outputs, a.outputs / "wilson_test"]:
        f = run / "incidents.json"
        if not f.exists():
            continue
        for inc in json.loads(f.read_text()):
            inc["run"] = run_name(run)
            s = scores.get(inc["scenario"])
            if s is None:
                missing.add(inc["scenario"])
                inc["model"] = None
            else:
                s0 = int(pd.Timestamp(inc["start"]).timestamp())
                e0 = int(pd.Timestamp(inc["end"]).timestamp())
                m = s.loc[(s.index >= s0) & (s.index < e0)]
                inc["model"] = {"score_col": a.score_col, "n_minutes": int(len(m)),
                                "p_max": round(float(m.max()), 6) if len(m) else None,
                                "p_mean": round(float(m.mean()), 6) if len(m) else None,
                                "peak_minute_utc": utc(int(m.idxmax())) if len(m) else None}
                n_scored += 1
            out.append(inc)

    out.sort(key=lambda i: (-(i["model"]["p_max"] if i["model"] and i["model"]["p_max"] is not None else -1), -i["peak_z"]))
    a.out_json.write_text(json.dumps(out, indent=2, allow_nan=False))
    print(f"{n_scored}/{len(out)} incidents scored with {a.score_col!r} -> {rel(a.out_json)}")
    if missing:
        print(f"no scores for {sorted(missing)} (model is null for those incidents)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["export", "attach"])
    ap.add_argument("--outputs", type=Path, default=ROOT / "outputs", help="stats stage output folder")
    ap.add_argument("--feat-dir", type=Path, default=ROOT / "dataset" / "features",
                    help="his <scenario>_features.csv (the minute grid to join onto) and *_scores.csv")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "outputs" / "model_input")
    ap.add_argument("--scores-dir", type=Path, default=None, help="attach: folder of *_scores.csv (default: --feat-dir)")
    ap.add_argument("--score-col", default="p_attack")
    ap.add_argument("--out-json", type=Path, default=ROOT / "outputs" / "incidents_scored.json")
    a = ap.parse_args()
    a.scores_dir = a.scores_dir or a.feat_dir
    {"export": cmd_export, "attach": cmd_attach}[a.mode](a)


if __name__ == "__main__":
    main()

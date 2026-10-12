#!/usr/bin/env python3
"""Stats stage: merged alerts -> entity windows -> robust z-scores -> phase check.

Run from the repo root:
    python stats_pipeline.py                          # russellmitchell only
    python stats_pipeline.py --all                    # all eight scenarios
    python stats_pipeline.py --scenarios fox wilson   # pick scenarios

Reads:   dataset/merged.jsonl, dataset/labels.csv
Writes:  outputs/stats_report.txt   (everything printed; upload this)
         outputs/plots/*.png        (timelines with attack phases shaded)
         outputs/windows_z.parquet  (scored windows)
         outputs/incidents.json     (flagged incidents for the classifier / Claude; no labels)
         outputs/incidents_eval.csv (incidents vs. attack phases; evaluation only)
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # save plots to files, never open windows
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ----------------------------------------------------------------------------- settings
ALL_SCENARIOS = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler", "wilson"]
WINDOW = "1min"
BURN_IN = pd.Timedelta("12h")       # first hours of each scenario: learn, don't flag
MAD_FLOOR = 0.5                     # z denominator floor so mostly-zero features don't explode
EVENT_MAD_FLOOR = 0.15              # smaller floor for rare-event features: one occurrence should matter
RARE_MAX = 3                        # a rule seen <= this many times in a scenario counts as "rare"
VOLUME_WEIGHT = 0.5                 # a pure volume spike counts half as much as a real signal
THRESHOLDS = [0.95, 0.98, 0.99, 0.995]
FLAG_Z = 4.0                        # incident threshold: z_max at or above this gets flagged
MERGE_GAP = pd.Timedelta("10min")   # flagged windows on one host closer than this merge into one incident
MAX_INCIDENT = pd.Timedelta("60min")  # split incidents longer than this so one can't swallow a whole day
SAMPLE_ALERTS = 10                  # raw alerts attached to each incident
INCIDENT_BUDGET = 40                # incidents.json keeps the top N per scenario (analyst / LLM workload)
EVAL_TOLERANCE = pd.Timedelta("2min")  # evaluation only: alerts are often logged just after a labeled phase ends

# feature name -> Wazuh rule groups that count toward it
CATEGORIES = {
    "web_attack":   ["attack", "web_scan", "recon", "appsec"],
    "auth_fail":    ["authentication_failed", "authentication_failures", "invalid_login", "access_denied"],
    "auth_success": ["authentication_success"],
    "priv":         ["sudo", "su"],
    "audit":        ["audit", "audit_selinux", "access_control"],
}
ROLLING = ["total", "new_rule", "high_level", "priv", "auth_fail"]   # get 60-min rolling sums
VOLUME_FEATURES = ["total", "is_wazuh", "is_suricata", "is_aminer", "n_rules"]
# sparse "something unusual happened" counts: usually 0, so a single 1 is meaningful
# (aminer_novel is NOT here: ~97% of AMiner alerts are "New ..." detections, so it isn't sparse;
#  with the small floor, routine AMiner bursts on quiet hosts were scoring z~25)
EVENT_FEATURES = ["new_rule", "rare_rule", "auth_success", "priv", "high_level"]

# attacker view: group alerts by SOURCE IP across all hosts (catches scans that touch
# each host only briefly but hit many hosts)
ACTOR_MIN_ALERTS = 20               # ignore source IPs with fewer alerts than this in a scenario
ACTOR_SIGNAL = ["n_targets", "n_ports", "sig_scan", "web_attack", "auth_fail"]
ACTOR_VOLUME = ["total", "n_rules"]

# plain-English text for each z_reason (shown to analysts and passed to Claude)
REASON_TEXT = {
    "web_attack": "burst of web-attack alerts (scans, exploits)",
    "auth_fail": "spike in failed logins",
    "auth_success": "successful login, rare for this host",
    "priv": "privilege use (sudo/su)",
    "audit": "audit / access-control events",
    "new_rule": "alert type never seen before on this host",
    "rare_rule": "alert type that is rare across the whole network",
    "aminer_novel": "AMiner flagged never-before-seen behavior",
    "high_level": "high-severity alerts (Wazuh level 10+)",
    "max_level": "unusually severe alert for this host",
    "sig_scan": "network-scan signatures (Suricata)",
    "total": "alert volume far above its normal",
    "is_wazuh": "Wazuh alert volume far above normal",
    "is_suricata": "network IDS alert volume far above normal",
    "is_aminer": "AMiner alert volume far above normal",
    "n_rules": "unusually many different alert types",
    "n_targets": "one source touching unusually many hosts (scan / lateral movement)",
    "n_ports": "one source probing unusually many ports",
}

KEEP = ["scenario", "ts", "source", "host", "host_name", "host_ip", "location", "detector",
        "detector_id", "src_ip", "dst_ip", "is_baseline", "raw", "extras"]
EXTRA_COLS = ["rule_level", "rule_groups", "signature", "detector_name", "dst_port"]


# ----------------------------------------------------------------------------- report helper
class Report:
    """Print to the terminal and to outputs/stats_report.txt at the same time."""

    def __init__(self, path: Path):
        self.f = path.open("w")

    def __call__(self, *args):
        text = " ".join(str(a) for a in args)
        print(text)
        self.f.write(text + "\n")
        self.f.flush()

    def section(self, title):
        self(f"\n=== {title} ===")


# ----------------------------------------------------------------------------- 1. load
def input_files(data_dir: Path, scenarios: list[str]) -> list[tuple[Path, str | None]]:
    """Prefer the new all-scenario merged.jsonl; fall back to old <scenario>_merged.jsonl files."""
    combined = data_dir / "merged.jsonl"
    if combined.exists():
        return [(combined, None)]
    files = [(data_dir / f"{s}_merged.jsonl", s) for s in scenarios]
    missing = [str(f) for f, _ in files if not f.exists()]
    if missing:
        sys.exit("No dataset/merged.jsonl, and missing per-scenario files:\n  " + "\n  ".join(missing)
                 + "\nRun scripts/merge_alerts.py on the raw AIT-ADS files first.")
    return files


def load_alerts(data_dir: Path, scenarios: list[str], say: Report) -> pd.DataFrame:
    parts = []
    for path, scen_from_name in input_files(data_dir, scenarios):
        say(f"reading {path.name}")
        for chunk in pd.read_json(path, lines=True, chunksize=200_000):
            if scen_from_name is not None:          # old per-scenario format has no scenario field
                chunk["scenario"] = scen_from_name
            chunk = chunk[chunk["scenario"].isin(scenarios)]
            if len(chunk):
                parts.append(chunk.reindex(columns=KEEP))
    if not parts:
        sys.exit(f"No rows for scenarios {scenarios}")
    raw = pd.concat(parts, ignore_index=True)

    ex = pd.json_normalize(raw.pop("extras").tolist()).reindex(columns=EXTRA_COLS)
    raw = pd.concat([raw, ex], axis=1)
    raw["ts"] = pd.to_datetime(raw["ts"], unit="s", utc=True)
    # Suricata alerts arrive through Wazuh; their location path gives them away
    raw["tool"] = np.where(raw["location"].fillna("").str.contains("suricata/"), "suricata", raw["source"])
    raw["rule_level"] = pd.to_numeric(raw["rule_level"], errors="coerce").fillna(0)
    raw["rule_key"] = np.where(raw["source"] == "wazuh",
                               "W" + raw["detector_id"].astype(str),
                               "A:" + raw["detector"].astype(str))
    n_loaded = len(raw)

    # parser keeps both eve.json and fast.log copies of each Suricata alert; keep one
    sur = raw["tool"] == "suricata"
    key = (raw.loc[sur, "signature"].astype(str) + "|" + raw.loc[sur, "src_ip"].astype(str) + "|"
           + raw.loc[sur, "dst_ip"].astype(str) + "|" + raw.loc[sur, "ts"].dt.floor("1s").astype(str))
    dups = key[key.duplicated()].index
    raw = raw.drop(dups).reset_index(drop=True)

    raw["entity"] = make_entities(raw)
    n_dedup = len(raw)
    raw = raw[~raw["is_baseline"].astype(bool)].copy()

    say.section("funnel: alerts")
    say(f"loaded:                     {n_loaded:>10,}")
    say(f"after Suricata dedup:       {n_dedup:>10,}  (-{len(dups):,} duplicate copies)")
    say(f"after baseline-rule filter: {len(raw):>10,}  (-{n_dedup - len(raw):,} known-benign)")
    return raw


def is_internal(v) -> bool:
    try:
        return ipaddress.ip_address(v).is_private
    except (ValueError, TypeError):
        return False


def strip_port(v):
    """'10.143.2.4:80' -> '10.143.2.4' (older parser output; leaves IPv6 alone)."""
    if isinstance(v, str) and v.count(":") == 1:
        return v.split(":")[0]
    return v if isinstance(v, str) and v else None


def make_entities(raw: pd.DataFrame) -> pd.Series:
    """One name per machine across tools: its internal IP."""
    both = raw.dropna(subset=["host_name", "host_ip"])
    name_to_ip = both.groupby("host_name")["host_ip"].agg(lambda s: s.mode().iat[0]).to_dict()
    host_entity = (raw["host_ip"].fillna(raw["host_name"].map(name_to_ip))
                   .fillna(raw["host_name"]).fillna(raw["host"].map(strip_port)))

    # Suricata: key on whichever side of the connection is inside the network
    src, dst = raw["src_ip"].map(strip_port), raw["dst_ip"].map(strip_port)
    suricata_entity = np.where(dst.map(is_internal), dst,
                               np.where(src.map(is_internal), src, "external"))
    ent = np.where(raw["tool"] == "suricata", suricata_entity, host_entity)
    return pd.Series(ent, index=raw.index).fillna("unknown")


def load_labels(path: Path, scenarios: list[str]) -> pd.DataFrame:
    labels = pd.read_csv(path)
    labels["start"] = pd.to_datetime(labels["start"], unit="s", utc=True)
    labels["end"] = pd.to_datetime(labels["end"], unit="s", utc=True)
    return labels[labels["scenario"].isin(scenarios)].reset_index(drop=True)


# ----------------------------------------------------------------------------- 2. checks
def sanity_checks(raw, labels, say: Report):
    say.section("tools")
    say(raw["tool"].value_counts().to_string())

    say.section("entities per tool (should be the same internal IPs)")
    for tool, ents in raw.groupby("tool")["entity"].unique().items():
        say(tool, sorted(map(str, ents))[:25])

    say.section("entity alert counts")
    say(raw.groupby(["scenario", "entity"]).size().sort_values(ascending=False).head(25).to_string())

    say.section("burn-in safety (time to first attack; must exceed burn-in)")
    gap = labels.groupby("scenario")["start"].min() - raw.groupby("scenario")["ts"].min()
    for scen, g in gap.items():
        flag = "OK" if g > BURN_IN else "TOO SHORT: lower BURN_IN"
        say(f"{scen:16s} {g}  {flag}")

    say.section("top Wazuh rule groups")
    say(raw.loc[raw.tool == "wazuh", "rule_groups"].explode().value_counts().head(30).to_string())


def shade_phases(ax, labels, scen):
    for _, p in labels[labels.scenario == scen].iterrows():
        ax.axvspan(p.start, p.end, color="tab:red", alpha=0.15)
        ax.text(p.start, ax.get_ylim()[1], p.attack, rotation=90, va="top", fontsize=7)


def plot_timelines(raw, labels, scenarios, plot_dir: Path):
    for scen in scenarios:
        d = raw[raw.scenario == scen]
        lab = labels[labels.scenario == scen]
        if d.empty or lab.empty:
            continue
        lo, hi = lab.start.min() - pd.Timedelta("1h"), lab.end.max() + pd.Timedelta("1h")
        for name, sub in [("full", d), ("attack", d[d.ts.between(lo, hi)])]:
            per_min = sub.groupby([pd.Grouper(key="ts", freq="1min"), "tool"]).size().unstack(fill_value=0)
            if per_min.empty:
                continue
            ax = per_min.plot(figsize=(16, 4), logy=True, lw=0.8, title=f"{scen}: alerts per minute ({name})")
            shade_phases(ax, labels, scen)
            plt.tight_layout()
            plt.savefig(plot_dir / f"{scen}_alerts_{name}.png", dpi=110)
            plt.close()


# ----------------------------------------------------------------------------- 3. aggregate
def alert_features(raw: pd.DataFrame, say: Report) -> pd.DataFrame:
    a = raw[["scenario", "entity", "ts", "tool", "rule_key", "rule_level", "rule_groups", "signature",
             "detector"]].copy()
    a["window"] = a["ts"].dt.floor(WINDOW)

    groups = a["rule_groups"].apply(lambda g: set(g) if isinstance(g, (list, np.ndarray)) else set())
    for name, gs in CATEGORIES.items():
        gs = set(gs)
        a[name] = groups.apply(lambda s: bool(s & gs)).astype(int)

    a["is_wazuh"] = (a.tool == "wazuh").astype(int)
    a["is_suricata"] = (a.tool == "suricata").astype(int)
    a["is_aminer"] = (a.tool == "aminer").astype(int)
    a["high_level"] = (a.rule_level >= 10).astype(int)
    a["sig_scan"] = a["signature"].fillna("").str.startswith("ET SCAN").astype(int)
    # AMiner "New value / New ... combination" detectors are novelty detections by definition
    a["aminer_novel"] = ((a.tool == "aminer")
                         & a["detector"].fillna("").str.contains(r"\bNew\b", regex=True)).astype(int)

    # novelty: first time this rule fires on this entity, ignoring the burn-in period
    a = a.sort_values("ts")
    a["new_rule"] = (~a.duplicated(["scenario", "entity", "rule_key"])).astype(int)
    scen_start = a.groupby("scenario")["ts"].transform("min")
    a.loc[a["ts"] < scen_start + BURN_IN, "new_rule"] = 0

    # rarity: rules that fire only a handful of times in the whole scenario
    rule_count = a.groupby(["scenario", "rule_key"])["rule_key"].transform("size")
    a["rare_rule"] = (rule_count <= RARE_MAX).astype(int)

    say.section("category hits (0 = group names don't match the data)")
    say(a[[*CATEGORIES, "new_rule", "rare_rule", "aminer_novel"]].sum().to_string())
    return a


def aggregate(a: pd.DataFrame) -> pd.DataFrame:
    keys = ["scenario", "entity", "window"]
    count_cols = ["is_wazuh", "is_suricata", "is_aminer", "high_level", "sig_scan", "new_rule", "rare_rule",
                  "aminer_novel", *CATEGORIES]
    g = a.groupby(keys)
    agg = g[count_cols].sum()
    agg["total"] = g.size()
    agg["max_level"] = g["rule_level"].max()
    agg["n_rules"] = g["rule_key"].nunique()
    agg["n_tools"] = (agg[["is_wazuh", "is_suricata", "is_aminer"]] > 0).sum(axis=1)

    # fill empty windows with zeros so baselines see quiet periods too
    parts = []
    for scen, s in agg.groupby(level="scenario"):
        s = s.droplevel("scenario")
        wins = s.index.get_level_values("window")
        full = pd.date_range(wins.min(), wins.max(), freq=WINDOW)
        ents = s.index.get_level_values("entity").unique()
        idx = pd.MultiIndex.from_product([ents, full], names=["entity", "window"])
        parts.append(pd.concat({scen: s.reindex(idx, fill_value=0)}, names=["scenario"]))
    agg = pd.concat(parts).sort_index()

    # short memory: rolling sums over the previous hour, per entity (Isolation Forest context)
    steps = int(pd.Timedelta("60min") / pd.Timedelta(WINDOW))
    for c in ROLLING:
        agg[f"{c}_60m"] = (agg.groupby(level=["scenario", "entity"])[c]
                              .transform(lambda x: x.rolling(steps, min_periods=1).sum()))
    return agg


# ----------------------------------------------------------------------------- 4. z-scores
def robust_z(x: pd.Series, floor: float = MAD_FLOOR) -> pd.Series:
    x = np.log1p(x.astype(float))
    med = x.median()
    mad = (x - med).abs().median()
    return (x - med) / max(1.4826 * mad, floor)


def score(agg: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    features = ["total", "is_wazuh", "is_suricata", "is_aminer", "high_level", "max_level",
                "n_rules", "new_rule", "rare_rule", "aminer_novel", "sig_scan", *CATEGORIES, *[f"{c}_60m" for c in ROLLING]]
    by_ent = agg.groupby(level=["scenario", "entity"])
    for c in features:
        floor = EVENT_MAD_FLOOR if c in EVENT_FEATURES else MAD_FLOOR
        agg[f"{c}_z"] = by_ent[c].transform(lambda x, f=floor: robust_z(x, f))
    z_cols = [f"{c}_z" for c in features]          # all of these go to Isolation Forest later

    # z_max: instantaneous features only (rolling ones would echo a burst for an hour),
    # and pure-volume features down-weighted versus meaningful signals
    inst = [c for c in z_cols if not c.endswith("_60m_z")]
    vol_cols = [f"{c}_z" for c in VOLUME_FEATURES]
    sig_cols = [c for c in inst if c not in vol_cols]
    sig = agg[sig_cols].max(axis=1)
    vol = agg[vol_cols].max(axis=1) * VOLUME_WEIGHT
    agg["z_max"] = np.maximum(sig, vol)
    agg["z_reason"] = pd.Series(
        np.where(sig >= vol, agg[sig_cols].idxmax(axis=1), agg[vol_cols].idxmax(axis=1)),
        index=agg.index).str.removesuffix("_z")

    # never flag burn-in windows (they still count toward each host's baseline)
    win = agg.index.get_level_values("window")
    scen = agg.index.get_level_values("scenario")
    start = pd.Series(win, index=agg.index).groupby(scen).transform("min")
    in_burn = win.values < (start + BURN_IN).values
    agg.loc[in_burn, "z_max"] = 0.0
    agg.loc[in_burn, "z_reason"] = "burn_in"
    return agg, z_cols


# ----------------------------------------------------------------------------- 5. check vs labels
def mark_attacks(agg, labels) -> pd.DataFrame:
    w = agg.reset_index()
    w["in_attack"] = False
    w["phase"] = None
    for _, p in labels.iterrows():
        m = overlaps(w, p)
        w.loc[m, "in_attack"] = True
        w.loc[m & w.phase.isna(), "phase"] = p.attack
    return w


def overlaps(df, p):
    return ((df.scenario == p.scenario) & (df.window < p.end + EVAL_TOLERANCE)
            & (df.window + pd.Timedelta(WINDOW) > p.start - EVAL_TOLERANCE))


def phase_recall(w, labels, thresh_pct):
    w = w.copy()
    w["pct"] = w.groupby("scenario")["z_max"].rank(pct=True)
    flagged = w[w.pct >= thresh_pct]
    rows = [{"scenario": p.scenario, "phase": p.attack, "detected": bool(overlaps(flagged, p).any())}
            for _, p in labels.iterrows()]
    prec = flagged["in_attack"].mean() if len(flagged) else float("nan")
    return pd.DataFrame(rows), len(flagged), prec


def phase_detail(w, labels) -> pd.DataFrame:
    """Best-scoring window inside each phase: is the detection real or a coincidence?"""
    w = w.copy()
    w["rank"] = w.groupby("scenario")["z_max"].rank(ascending=False, method="min").astype(int)
    n_per = w.groupby("scenario").size()
    rows = []
    for _, p in labels.iterrows():
        best = w[overlaps(w, p)].sort_values("z_max", ascending=False).head(1)
        if best.empty:
            rows.append({"scenario": p.scenario, "phase": p.attack, "rank": None})
            continue
        b = best.iloc[0]
        rows.append({"scenario": p.scenario, "phase": p.attack, "rank": int(b["rank"]),
                     "of": int(n_per[p.scenario]), "top_pct": round(100 * b["rank"] / n_per[p.scenario], 2),
                     "entity": b.entity, "z": round(float(b.z_max), 1),
                     "reason": b.z_reason, "alerts": int(b.total)})
    return pd.DataFrame(rows)


def plot_zmax(w, labels, scenarios, plot_dir: Path):
    for scen in scenarios:
        d = w[w.scenario == scen]
        lab = labels[labels.scenario == scen]
        if d.empty or lab.empty:
            continue
        peak = d.groupby("window")["z_max"].max()
        lo, hi = lab.start.min() - pd.Timedelta("6h"), lab.end.max() + pd.Timedelta("6h")
        ax = peak[lo:hi].plot(figsize=(16, 4), lw=0.8, title=f"{scen}: max z across entities")
        shade_phases(ax, labels, scen)
        plt.tight_layout()
        plt.savefig(plot_dir / f"{scen}_zmax.png", dpi=110)
        plt.close()


def missed_phases(raw, labels, res, say: Report):
    missed = res.loc[~res.detected]
    if missed.empty:
        return
    say.section("what the missed phases produced (few/none distinctive = invisible to IDS)")
    for _, row in missed.iterrows():
        p = labels[(labels.scenario == row.scenario) & (labels.attack == row.phase)].iloc[0]
        d = raw[(raw.scenario == p.scenario)
                & raw.ts.between(p.start - pd.Timedelta("5min"), p.end + pd.Timedelta("5min"))]
        say(f"\n--- {p.scenario} / {p.attack}: {len(d)} alerts "
            f"({p.start:%m-%d %H:%M:%S} to {p.end:%m-%d %H:%M:%S}) ---")
        if len(d):
            say(d.groupby(["tool", "entity", "detector"]).size()
                 .sort_values(ascending=False).head(12).to_string())


# ----------------------------------------------------------------------------- 5b. attacker view
def actor_view(raw: pd.DataFrame, say: Report):
    """Group alerts by source IP across all hosts. Returns (scored actor windows, actor raw, z_cols)."""
    r = raw[raw["src_ip"].notna()].copy()
    r["actor"] = r["src_ip"].map(strip_port)
    r = r[r["actor"].notna() & (r["actor"] != r["entity"])]     # source acting on some other host
    counts = r.groupby(["scenario", "actor"]).size()
    keep = counts[counts >= ACTOR_MIN_ALERTS].index
    r = r.set_index(["scenario", "actor"]).loc[lambda d: d.index.isin(keep)].reset_index()
    if r.empty:
        say("actor view: no source IPs with enough alerts")
        return None, None, []

    groups = r["rule_groups"].apply(lambda g: set(g) if isinstance(g, (list, np.ndarray)) else set())
    for name in ["web_attack", "auth_fail"]:
        gs = set(CATEGORIES[name])
        r[name] = groups.apply(lambda s: bool(s & gs)).astype(int)
    r["sig_scan"] = r["signature"].fillna("").str.startswith("ET SCAN").astype(int)
    r["window"] = r["ts"].dt.floor(WINDOW)

    g = r.groupby(["scenario", "actor", "window"])
    agg = g[["sig_scan", "web_attack", "auth_fail"]].sum()
    agg["total"] = g.size()
    agg["n_targets"] = g["entity"].nunique()
    agg["n_ports"] = g["dst_port"].nunique()
    agg["n_rules"] = g["rule_key"].nunique()

    # zero-fill each actor across its scenario's full time range
    parts = []
    for scen, s in agg.groupby(level="scenario"):
        s = s.droplevel("scenario")
        t = raw.loc[raw.scenario == scen, "ts"]
        full = pd.date_range(t.min().floor(WINDOW), t.max().floor(WINDOW), freq=WINDOW)
        idx = pd.MultiIndex.from_product([s.index.get_level_values("actor").unique(), full],
                                         names=["actor", "window"])
        parts.append(pd.concat({scen: s.reindex(idx, fill_value=0)}, names=["scenario"]))
    agg = pd.concat(parts).sort_index()
    agg.index = agg.index.set_names(["scenario", "entity", "window"])   # same shape as host view

    by = agg.groupby(level=["scenario", "entity"])
    feats = ACTOR_SIGNAL + ACTOR_VOLUME
    for c in feats:
        agg[f"{c}_z"] = by[c].transform(robust_z)
    sig_cols = [f"{c}_z" for c in ACTOR_SIGNAL]
    vol_cols = [f"{c}_z" for c in ACTOR_VOLUME]
    sig = agg[sig_cols].max(axis=1)
    vol = agg[vol_cols].max(axis=1) * VOLUME_WEIGHT
    agg["z_max"] = np.maximum(sig, vol)
    agg["z_reason"] = pd.Series(
        np.where(sig >= vol, agg[sig_cols].idxmax(axis=1), agg[vol_cols].idxmax(axis=1)),
        index=agg.index).str.removesuffix("_z")

    win = agg.index.get_level_values("window")
    start = pd.Series(win, index=agg.index).groupby(agg.index.get_level_values("scenario")).transform("min")
    in_burn = win.values < (start + BURN_IN).values
    agg.loc[in_burn, "z_max"] = 0.0
    agg.loc[in_burn, "z_reason"] = "burn_in"

    actor_raw = r.rename(columns={"entity": "victim"}).rename(columns={"actor": "entity"})
    say.section("attacker view (alerts grouped by source IP across hosts)")
    say(f"{agg.index.droplevel('window').nunique()} source IPs with >= {ACTOR_MIN_ALERTS} alerts, "
        f"{len(agg):,} actor-windows")
    say(agg[["total", "n_targets", "n_ports", "z_max", "z_reason"]]
        .sort_values("z_max", ascending=False).head(15).to_string())
    return agg, actor_raw, [f"{c}_z" for c in feats]


# ----------------------------------------------------------------------------- 6. incidents
def window_reasons(row, z_cols, top=3):
    """Top features (z >= 2) for one window, as (name, z) pairs."""
    zs = row[z_cols]
    zs = zs[zs >= 2].sort_values(ascending=False).head(top)
    return [(c.removesuffix("_z"), float(v)) for c, v in zs.items()]


def clean(v):
    """NaN/None -> None so the JSON is valid for any reader."""
    return None if v is None or (isinstance(v, float) and np.isnan(v)) else v


def build_incidents(agg, raw, z_cols, say: Report, kind: str = "host") -> list[dict]:
    """raw must have an 'entity' column matching agg's entity level (host IP, or source IP for actors)."""
    inst = [c for c in z_cols if not c.endswith("_60m_z")]
    f = agg[agg["z_max"] >= FLAG_Z].reset_index().sort_values(["scenario", "entity", "window"])
    if f.empty:
        say("no windows at or above FLAG_Z; lower it")
        return []

    # merge flagged windows on the same host that are close in time
    inc_ids, cur, prev_key, inc_start, prev_win = [], -1, None, None, None
    for key, win in zip(zip(f["scenario"], f["entity"]), f["window"]):
        if key != prev_key or win - prev_win > MERGE_GAP or win - inc_start >= MAX_INCIDENT:
            cur, inc_start = cur + 1, win
        inc_ids.append(cur)
        prev_key, prev_win = key, win
    f["inc"] = inc_ids

    win_len = pd.Timedelta(WINDOW)
    raw_by = {k: g for k, g in raw.groupby(["scenario", "entity"])}
    incidents = []
    for (scen, ent, _), g in f.groupby(["scenario", "entity", "inc"]):
        start, end = g["window"].min(), g["window"].max() + win_len
        alerts = raw_by[(scen, ent)]
        alerts = alerts[(alerts.ts >= start) & (alerts.ts < end)]

        # reasons: strongest z per feature across the incident's windows
        best = {}
        for _, row in g.iterrows():
            for name, z in window_reasons(row, inst):
                best[name] = max(best.get(name, 0), z)
        reasons = [{"feature": k, "z": round(v, 1), "text": REASON_TEXT.get(k, k)}
                   for k, v in sorted(best.items(), key=lambda kv: -kv[1])]

        top_rules = (alerts.groupby(["tool", "detector"]).size().sort_values(ascending=False).head(5))
        # samples: most severe first, then one per distinct detector so variety shows
        samp = (alerts.sort_values(["rule_level", "ts"], ascending=[False, True])
                      .drop_duplicates("detector").head(SAMPLE_ALERTS))
        incidents.append({
            "kind": kind,
            "scenario": scen,
            "entity": ent,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "peak_z": round(float(g["z_max"].max()), 1),
            "n_windows": int(len(g)),
            "n_alerts": int(len(alerts)),
            "tools": sorted(alerts["tool"].unique().tolist()),
            "targets": (sorted(alerts["victim"].dropna().unique().tolist())[:20]
                        if kind == "actor" and "victim" in alerts else None),
            "reasons": reasons,
            "top_rules": [{"tool": t, "detector": d, "count": int(c)} for (t, d), c in top_rules.items()],
            "sample_alerts": [{"ts": r.ts.isoformat(), "tool": r.tool, "detector": r.detector,
                               "level": int(r.rule_level), "src_ip": clean(r.src_ip), "dst_ip": clean(r.dst_ip),
                               "raw": (str(r.raw)[:500] if pd.notna(r.raw) else None)}
                              for r in samp.itertuples()],
        })

    return incidents


def finalize_incidents(incidents: list[dict]) -> list[dict]:
    """Rank, assign ids, and link incidents that overlap in time (same attack, other side)."""
    incidents.sort(key=lambda i: -i["peak_z"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:04d}"
    for inc in incidents:
        s0, e0 = pd.Timestamp(inc["start"]), pd.Timestamp(inc["end"])
        inc["related"] = [o["incident_id"] for o in incidents
                          if o is not inc and o["scenario"] == inc["scenario"]
                          and pd.Timestamp(o["start"]) < e0 + pd.Timedelta("5min")
                          and pd.Timestamp(o["end"]) > s0 - pd.Timedelta("5min")]
    return [{"incident_id": i.pop("incident_id"), **i} for i in incidents]


def evaluate_incidents(incidents, labels, n_alerts, say: Report) -> pd.DataFrame:
    rows = []
    for inc in incidents:
        s0, e0 = pd.Timestamp(inc["start"]), pd.Timestamp(inc["end"])
        lab = labels[(labels.scenario == inc["scenario"]) & (labels.start - EVAL_TOLERANCE < e0)
                     & (labels.end + EVAL_TOLERANCE > s0)]
        rows.append({"incident_id": inc["incident_id"], "kind": inc["kind"],
                     "scenario": inc["scenario"], "entity": inc["entity"],
                     "start": inc["start"], "peak_z": inc["peak_z"], "n_alerts": inc["n_alerts"],
                     "top_reason": inc["reasons"][0]["feature"] if inc["reasons"] else "",
                     "phases": ",".join(lab.attack)})
    ev = pd.DataFrame(rows)
    if ev.empty:
        say("no incidents")
        return ev
    ev["rank_in_scenario"] = ev.groupby("scenario")["peak_z"].rank(ascending=False, method="first").astype(int)
    ev["in_budget"] = ev["rank_in_scenario"] <= INCIDENT_BUDGET

    say.section(f"incidents (FLAG_Z={FLAG_Z}, merge gap={MERGE_GAP}, budget={INCIDENT_BUDGET}/scenario, "
                f"eval tolerance={EVAL_TOLERANCE})")
    n_att = (ev.phases != "").sum()
    say(f"{n_alerts:,} alerts -> {len(ev):,} incidents ({n_att} overlap an attack phase); "
        f"top {INCIDENT_BUDGET} per scenario -> {int(ev.in_budget.sum())} handed off")

    rows = []
    for scen, lab in labels.groupby("scenario"):
        se = ev[ev.scenario == scen]
        row = {"scenario": scen, "phases": len(lab), "incidents": len(se)}
        for name, sub in [("all", se), ("budget", se[se.in_budget]),
                          ("budget_host", se[se.in_budget & (se.kind == "host")]),
                          ("budget_actor", se[se.in_budget & (se.kind == "actor")])]:
            covered = set(",".join(sub.phases).split(",")) - {""}
            row[name] = len([p for p in lab.attack if p in covered])
        b = se[se.in_budget]
        row["budget_precision"] = f"{(b.phases != '').mean():.0%}" if len(b) else "-"
        covered = set(",".join(b.phases).split(",")) - {""}
        row["missed_in_budget"] = ",".join(p for p in lab.attack if p not in covered)
        rows.append(row)
    say("phases covered per scenario (all incidents / within budget / budget host-only / budget actor-only):")
    say(pd.DataFrame(rows).to_string(index=False))

    say(f"\ntop 25 incidents:")
    say(ev.sort_values("peak_z", ascending=False).head(25).drop(columns=["in_budget"]).to_string(index=False))
    return ev


# ----------------------------------------------------------------------------- main
def find_repo_root() -> Path:
    """Walk up from the current folder and from this script's folder to the one holding dataset/.
    Lets the script run from anywhere: repo root, notebooks/, or IntelliJ's Run button."""
    starts = [Path.cwd(), Path(__file__).resolve().parent]
    for start in starts:
        for d in [start, *start.parents]:
            ds = d / "dataset"
            if (ds / "labels.csv").exists() and any(ds.glob("*merged.jsonl")):
                return d
    return Path.cwd()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = find_repo_root()
    ap.add_argument("--data-dir", type=Path, default=root / "dataset")
    ap.add_argument("--out-dir", type=Path, default=root / "outputs")
    ap.add_argument("--scenarios", nargs="+", default=["russellmitchell"])
    ap.add_argument("--all", action="store_true", help="run all eight scenarios")
    ap.add_argument("--window", default=None, help='window size to try, e.g. "1min" (default 5min)')
    args = ap.parse_args()

    scenarios = ALL_SCENARIOS if args.all else args.scenarios
    if args.window:
        global WINDOW
        WINDOW = args.window
    labels_path = args.data_dir / "labels.csv"
    if not labels_path.exists():
        sys.exit(f"Missing {labels_path}. Run from the repo root or pass --data-dir.")
    plot_dir = args.out_dir / "plots"
    plot_dir.mkdir(parents=True, exist_ok=True)
    say = Report(args.out_dir / "stats_report.txt")
    say(f"scenarios: {scenarios}")
    say(f"settings: window={WINDOW} burn_in={BURN_IN} mad_floor={MAD_FLOOR} "
        f"event_floor={EVENT_MAD_FLOOR} rare_max={RARE_MAX} volume_weight={VOLUME_WEIGHT}")

    raw = load_alerts(args.data_dir, scenarios, say)
    labels = load_labels(labels_path, scenarios)
    sanity_checks(raw, labels, say)
    plot_timelines(raw, labels, scenarios, plot_dir)

    a = alert_features(raw, say)
    agg = aggregate(a)
    agg, z_cols = score(agg)

    say.section("funnel: windows")
    say(f"entity-windows: {len(agg):,}  (from {len(a):,} alerts)")

    say.section("top windows by z_max")
    top = agg[["total", "z_max", "z_reason"]].sort_values("z_max", ascending=False).head(20)
    say(top.to_string())

    w = mark_attacks(agg, labels)
    plot_zmax(w, labels, scenarios, plot_dir)

    say.section("phase recall by threshold (precision = flagged windows inside an attack)")
    for t in THRESHOLDS:
        r, n, prec = phase_recall(w, labels, t)
        say(f"top {100 * (1 - t):4.1f}%: {n:6,} flagged | phases {r.detected.sum()}/{len(r)} | precision {prec:.0%}")

    res, _, _ = phase_recall(w, labels, 0.99)
    say.section("best window inside each phase (real detection = attacked host + sensible reason)")
    say(phase_detail(w, labels).to_string())

    missed_phases(raw, labels, res, say)

    actor_agg, actor_raw, actor_z = actor_view(raw, say)
    if actor_agg is not None:
        aw = mark_attacks(actor_agg, labels)
        say.section("attacker view: best window inside each phase")
        say(phase_detail(aw, labels).to_string())

    incidents = build_incidents(agg, raw, z_cols, say, kind="host")
    if actor_agg is not None:
        incidents += build_incidents(actor_agg, actor_raw, actor_z, say, kind="actor")
    incidents = finalize_incidents(incidents)
    ev = evaluate_incidents(incidents, labels, len(raw), say)
    import json
    keep = set(ev.loc[ev["in_budget"], "incident_id"]) if len(ev) else set()
    handoff = [i for i in incidents if i["incident_id"] in keep]
    (args.out_dir / "incidents.json").write_text(json.dumps(handoff, indent=2, default=str, allow_nan=False))
    ev.to_csv(args.out_dir / "incidents_eval.csv", index=False)

    agg.to_parquet(args.out_dir / "windows_z.parquet")
    say(f"\nwrote {args.out_dir}/: windows_z.parquet, incidents.json, incidents_eval.csv, "
        f"stats_report.txt, plots/")


if __name__ == "__main__":
    main()

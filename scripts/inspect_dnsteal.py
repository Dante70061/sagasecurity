#!/usr/bin/env python3
"""Diagnostic: what fires during DNS exfiltration that doesn't fire normally?

For each dev scenario (never wilson), compares alerts during the labeled dnsteal hour
with the same hour exactly 24h earlier, per (host, tool, detector/signature).
Large "during vs before" ratios point at a usable signal.

Run from the repo root:  python scripts/inspect_dnsteal.py
Writes:                  outputs/dnsteal_report.txt
"""

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

DEV = ["fox", "harrison", "russellmitchell", "santos", "shaw", "wardbeck", "wheeler"]   # never wilson
PHASE = "dnsteal"
BASELINE_SHIFT = pd.Timedelta("24h")


def find_root() -> Path:
    for start in [Path.cwd(), Path(__file__).resolve().parent]:
        for d in [start, *start.parents]:
            if (d / "dataset" / "merged.jsonl").exists():
                return d
    sys.exit("dataset/merged.jsonl not found")


def key_of(e: dict) -> tuple:
    loc = e.get("location") or ""
    tool = "suricata" if "suricata/" in loc else e.get("source")
    ex = e.get("extras") or {}
    what = ex.get("signature") or e.get("detector") or "?"
    host = e.get("host_ip") or e.get("host_name") or e.get("host")
    if tool == "suricata":
        host = f'{e.get("src_ip")} -> {e.get("dst_ip")}'
    return tool, host, what


def main():
    root = find_root()
    labels = pd.read_csv(root / "dataset" / "labels.csv")
    labels = labels[(labels.attack == PHASE) & labels.scenario.isin(DEV)]
    spans = {}   # scenario -> (during_start, during_end, before_start, before_end) as epoch floats
    for _, p in labels.iterrows():
        shift = BASELINE_SHIFT.total_seconds()
        spans[p.scenario] = (p.start, p.end, p.start - shift, p.end - shift)

    during = {s: Counter() for s in spans}
    before = {s: Counter() for s in spans}
    with open(root / "dataset" / "merged.jsonl") as f:
        for line in f:
            e = json.loads(line)
            s = e.get("scenario")
            if s not in spans or e.get("is_baseline"):
                continue
            ts = e["ts"]
            d0, d1, b0, b1 = spans[s]
            if d0 <= ts < d1:
                during[s][key_of(e)] += 1
            elif b0 <= ts < b1:
                before[s][key_of(e)] += 1

    out = [f"DNS exfiltration diagnostic: '{PHASE}' hour vs same hour 24h earlier (dev scenarios only)\n"]
    for s in spans:
        rows = []
        for k, n in during[s].items():
            b = before[s].get(k, 0)
            rows.append({"tool": k[0], "host": k[1], "detector/signature": str(k[2])[:90],
                         "during": n, "day_before": b, "ratio": round((n + 1) / (b + 1), 1)})
        df = pd.DataFrame(rows)
        out.append(f"\n=== {s}: {sum(during[s].values())} alerts during, "
                   f"{sum(before[s].values())} same hour day before ===")
        if df.empty:
            out.append("(no alerts during the exfiltration hour)")
            continue
        out.append(df.sort_values(["ratio", "during"], ascending=False).head(15).to_string(index=False))

    text = "\n".join(out)
    print(text)
    (root / "outputs").mkdir(exist_ok=True)
    (root / "outputs" / "dnsteal_report.txt").write_text(text)
    print(f"\nwrote {root / 'outputs' / 'dnsteal_report.txt'}")


if __name__ == "__main__":
    main()
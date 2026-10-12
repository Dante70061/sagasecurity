#!/usr/bin/env python3
"""Normalize AMiner + Wazuh JSONL into one sorted event stream."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# Apache combined / common log
APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[.*?\] "(?P<method>\S+)\s+(?P<path>\S+)(?:\s+HTTP/\S+)?" '
    r'(?P<status>\d{3}) \S+(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
# Suricata fast.log: {TCP} src:port -> dst:port
SURICATA_FAST_RE = re.compile(
    r"\{(?P<proto>\w+)\}\s+(?P<src_ip>[^\s:]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[^\s:]+):(?P<dst_port>\d+)"
)
# DNS query from <ip>
DNS_FROM_RE = re.compile(r"\bfrom\s+(\d+\.\d+\.\d+\.\d+)\b")
# Generic IPv4
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

BASELINE_WAZUH_RULES = {"9701", "52507"}  # Dovecot success, ClamAV update


def parse_iso_ts(value: str) -> float:
    value = value.replace("Z", "+00:00").replace("+0000", "+00:00")
    return datetime.fromisoformat(value).timestamp()


def parse_apache(raw: str) -> dict[str, Any]:
    m = APACHE_RE.match(raw)
    if not m:
        return {}
    out: dict[str, Any] = {
        "src_ip": m.group("ip"),
        "http_method": m.group("method"),
        "http_path": m.group("path"),
        "status": m.group("status"),
    }
    if m.group("ua") is not None:
        out["ua"] = m.group("ua")
    if m.group("referer") is not None:
        out["referer"] = m.group("referer")
    return out


def first_ip(text: str | None) -> str | None:
    if not text:
        return None
    m = IPV4_RE.search(text)
    return m.group(0) if m else None


def normalize_aminer(obj: dict[str, Any]) -> dict[str, Any] | None:
    log = obj.get("LogData") or {}
    stamps = log.get("Timestamps") or []
    if not stamps:
        return None
    ac = obj.get("AnalysisComponent") or {}
    raws = log.get("RawLogData") or []
    raw = raws[0] if raws else ""
    resources = log.get("LogResources") or []
    location = resources[0] if resources else None

    extras: dict[str, Any] = {
        "detector_type": ac.get("AnalysisComponentType"),
        "detector_name": ac.get("AnalysisComponentName"),
        "message": ac.get("Message"),
        "training_mode": ac.get("TrainingMode"),
    }
    if "AffectedLogAtomValues" in ac:
        extras["affected_values"] = ac.get("AffectedLogAtomValues")

    parsed = parse_apache(raw) if location and "access" in location else {}
    src_ip = parsed.get("src_ip")
    if not src_ip:
        m = DNS_FROM_RE.search(raw)
        src_ip = m.group(1) if m else first_ip(raw)

    event = {
        "ts": float(stamps[0]),
        "source": "aminer",
        "host": (obj.get("AMiner") or {}).get("ID"),
        "location": location,
        "detector": ac.get("AnalysisComponentName") or ac.get("AnalysisComponentType"),
        "detector_id": str(ac.get("AnalysisComponentIdentifier"))
        if ac.get("AnalysisComponentIdentifier") is not None
        else None,
        "raw": raw,
        "src_ip": src_ip,
        "dst_ip": None,
        "http_path": parsed.get("http_path"),
        "http_method": parsed.get("http_method"),
        "status": parsed.get("status"),
        "ua": parsed.get("ua"),
        "is_baseline": False,
        "extras": extras,
    }
    return event


def normalize_wazuh(obj: dict[str, Any]) -> dict[str, Any] | None:
    ts_raw = obj.get("@timestamp") or obj.get("timestamp")
    if not ts_raw:
        return None
    try:
        ts = parse_iso_ts(ts_raw)
    except ValueError:
        return None

    rule = obj.get("rule") or {}
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    agent = obj.get("agent") or {}
    full_log = obj.get("full_log") or ""
    location = obj.get("location")

    rule_id = str(rule.get("id")) if rule.get("id") is not None else None
    description = rule.get("description") or ""

    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dest_ip")
    src_port = data.get("srcport") or data.get("src_port")
    dst_port = data.get("dstport") or data.get("dest_port")

    http_path = data.get("url")
    http_method = data.get("protocol")  # web-accesslog decoder uses this for method
    status = data.get("id") if location and "access" in (location or "") else None
    ua = None

    if full_log and (not src_ip or not http_path or not ua):
        parsed = parse_apache(full_log)
        src_ip = src_ip or parsed.get("src_ip")
        http_path = http_path or parsed.get("http_path")
        http_method = http_method or parsed.get("http_method")
        status = status or parsed.get("status")
        ua = parsed.get("ua")

    if location and "suricata/fast.log" in location and full_log:
        m = SURICATA_FAST_RE.search(full_log)
        if m:
            src_ip = src_ip or m.group("src_ip")
            dst_ip = dst_ip or m.group("dst_ip")
            src_port = src_port or m.group("src_port")
            dst_port = dst_port or m.group("dst_port")

    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    raw = full_log
    if not raw and alert:
        raw = alert.get("signature") or json.dumps(data, separators=(",", ":"))

    extras: dict[str, Any] = {
        "rule_level": rule.get("level"),
        "rule_groups": rule.get("groups"),
        "decoder": (obj.get("decoder") or {}).get("name"),
        "wazuh_id": obj.get("id"),
    }
    if alert:
        extras["signature"] = alert.get("signature")
        extras["signature_id"] = alert.get("signature_id")
    if src_port is not None:
        extras["src_port"] = str(src_port)
    if dst_port is not None:
        extras["dst_port"] = str(dst_port)

    host = agent.get("ip") or agent.get("name")

    return {
        "ts": ts,
        "source": "wazuh",
        "host": host,
        "location": location,
        "detector": f"{rule_id}: {description}" if rule_id else description,
        "detector_id": rule_id,
        "raw": raw,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "http_path": http_path,
        "http_method": http_method,
        "status": str(status) if status is not None else None,
        "ua": ua,
        "is_baseline": rule_id in BASELINE_WAZUH_RULES,
        "extras": extras,
    }


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def suricata_flow_key(event: dict[str, Any]) -> tuple | None:
    if event["source"] != "wazuh":
        return None
    loc = event.get("location") or ""
    if "suricata/" not in loc:
        return None
    extras = event.get("extras") or {}
    if not (event.get("src_ip") and event.get("dst_ip")):
        return None
    return (
        event["src_ip"],
        extras.get("src_port"),
        event["dst_ip"],
        extras.get("dst_port"),
        extras.get("signature") or event.get("detector"),
    )


def dedup_suricata(events: list[dict[str, Any]], window_s: float = 1.0) -> list[dict[str, Any]]:
    """Drop eve/fast duplicates of the same flow+signature within window_s."""
    out: list[dict[str, Any]] = []
    recent: dict[tuple, float] = {}
    for event in events:
        key = suricata_flow_key(event)
        if key is None:
            out.append(event)
            continue
        prev = recent.get(key)
        if prev is not None and abs(event["ts"] - prev) <= window_s:
            continue
        recent[key] = event["ts"]
        out.append(event)
    return out


def merge(
    aminer_path: Path,
    wazuh_path: Path,
    *,
    dedup: bool = True,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for obj in iter_jsonl(aminer_path):
        ev = normalize_aminer(obj)
        if ev:
            events.append(ev)
    for obj in iter_jsonl(wazuh_path):
        ev = normalize_wazuh(obj)
        if ev:
            events.append(ev)
    events.sort(key=lambda e: (e["ts"], e["source"], e.get("detector") or ""))
    if dedup:
        events = dedup_suricata(events)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--aminer",
        type=Path,
        default=Path("dataset/russellmitchell_aminer.json"),
    )
    parser.add_argument(
        "--wazuh",
        type=Path,
        default=Path("dataset/russellmitchell_wazuh.json"),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("dataset/russellmitchell_merged.jsonl"),
    )
    parser.add_argument("--no-dedup", action="store_true")
    args = parser.parse_args()

    events = merge(args.aminer, args.wazuh, dedup=not args.no_dedup)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
            f.write("\n")

    n_amin = sum(1 for e in events if e["source"] == "aminer")
    n_waz = sum(1 for e in events if e["source"] == "wazuh")
    n_base = sum(1 for e in events if e["is_baseline"])
    print(
        f"Wrote {len(events)} events -> {args.output} "
        f"(aminer={n_amin}, wazuh={n_waz}, baseline={n_base})"
    )


if __name__ == "__main__":
    main()

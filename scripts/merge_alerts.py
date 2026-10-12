#!/usr/bin/env python3
"""Merge AMiner + Wazuh JSONL alerts for every scenario in a folder.

Usage:
    python3 scripts/merge_alerts.py /path/to/unzipped/ait_ads
    python3 scripts/merge_alerts.py /path/to/unzipped/ait_ads -o dataset/merged.jsonl

Expects files named <scenario>_aminer.json and <scenario>_wazuh.json
(JSON Lines, despite the .json suffix). Writes one JSONL stream.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
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
# [**] [gid:sid:rev] signature [**]
FAST_SIG_RE = re.compile(
    r"\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]"
)
# "Jan 21 00:00:01 cloud-share CRON[4388]: ..."
SYSLOG_HOST_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)"
)
DNS_FROM_RE = re.compile(r"\bfrom\s+(\d+\.\d+\.\d+\.\d+)\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV4_FULL_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

BASELINE_WAZUH_RULES = {"9701", "52507"}  # Dovecot success, ClamAV update
# eve.json and fast.log copies of one alert share a timestamp.
# The opposite direction is a different alert (~40ms later) and must be kept.
SURICATA_DEDUP_WINDOW_S = 0.05


def parse_iso_ts(value: str) -> float:
    value = value.replace("Z", "+00:00").replace("+0000", "+00:00")
    return datetime.fromisoformat(value).timestamp()


def norm_sid(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d+\.0+", text):
        return text.split(".", 1)[0]
    return text or None


def parse_apache(raw: str) -> dict[str, Any]:
    match = APACHE_RE.match(raw)
    if not match:
        return {}
    out: dict[str, Any] = {
        "src_ip": match.group("ip"),
        "http_method": match.group("method"),
        "http_path": match.group("path"),
        "status": match.group("status"),
    }
    if match.group("ua") is not None:
        out["ua"] = match.group("ua")
    if match.group("referer") is not None:
        out["referer"] = match.group("referer")
    return out


def peel_ip_port(ip: Any, port: Any) -> tuple[Any, Any]:
    """Wazuh sometimes stores fast.log endpoints as 'ip:port' in the IP field."""
    if isinstance(ip, str) and ":" in ip:
        left, right = ip.rsplit(":", 1)
        if IPV4_FULL_RE.fullmatch(left) and right.isdigit():
            return left, port or right
    return ip, port


def first_ip(text: str | None) -> str | None:
    if not text:
        return None
    match = IPV4_RE.search(text)
    return match.group(0) if match else None


def syslog_host(raw: str | None) -> str | None:
    if not raw:
        return None
    match = SYSLOG_HOST_RE.match(raw)
    if not match:
        return None
    host = match.group(1)
    # Lines with no hostname put the program here: "dnsmasq[3326]:"
    if host in {"-", "wazuh-client"} or "[" in host or host.endswith(":"):
        return None
    return host


def resolve_host(
    ip_candidate: str | None,
    name_candidate: str | None,
    raw: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Return (host, host_name, host_ip). host is 'name (ip)' when both exist."""
    ip = ip_candidate.strip() if isinstance(ip_candidate, str) and ip_candidate.strip() else None
    name = (
        name_candidate.strip()
        if isinstance(name_candidate, str) and name_candidate.strip()
        else None
    )
    if name in {"wazuh-client", "-"}:
        name = None
    if ip and not IPV4_FULL_RE.fullmatch(ip):
        name = name or ip
        ip = None
    if name and IPV4_FULL_RE.fullmatch(name):
        ip = ip or name
        name = None
    if name is None:
        parsed = syslog_host(raw)
        if parsed and IPV4_FULL_RE.fullmatch(parsed):
            ip = ip or parsed
        elif parsed:
            name = parsed
    if name and ip and name == ip:
        name = None
    if name and ip:
        host = f"{name} ({ip})"
    else:
        host = name or ip
    return host, name, ip


def parse_fast_signature(raw: str) -> tuple[str | None, str | None]:
    match = FAST_SIG_RE.search(raw)
    if not match:
        return None, None
    return match.group(2), match.group(4).strip()


def normalize_aminer(obj: dict[str, Any], scenario: str) -> dict[str, Any] | None:
    ac = obj.get("AnalysisComponent") or {}
    # Cold-start rows are labeled training and are not detections.
    if ac.get("TrainingMode") is True:
        return None

    log = obj.get("LogData") or {}
    stamps = log.get("Timestamps") or []
    if not stamps:
        return None
    raws = log.get("RawLogData") or []
    raw = raws[0] if raws else ""
    resources = log.get("LogResources") or []
    location = resources[0] if resources else None

    extras: dict[str, Any] = {
        "detector_type": ac.get("AnalysisComponentType"),
        "detector_name": ac.get("AnalysisComponentName"),
        "message": ac.get("Message"),
    }
    if "AffectedLogAtomValues" in ac:
        extras["affected_values"] = ac.get("AffectedLogAtomValues")

    parsed = parse_apache(raw) if location and "access" in location else {}
    src_ip = parsed.get("src_ip")
    if not src_ip:
        dns_from = DNS_FROM_RE.search(raw)
        src_ip = dns_from.group(1) if dns_from else first_ip(raw)

    aminer_id = (obj.get("AMiner") or {}).get("ID")
    host, host_name, host_ip = resolve_host(
        aminer_id if isinstance(aminer_id, str) else None,
        None,
        raw,
    )

    return {
        "scenario": scenario,
        "ts": float(stamps[0]),
        "source": "aminer",
        "host": host,
        "host_name": host_name,
        "host_ip": host_ip,
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


def normalize_wazuh(obj: dict[str, Any], scenario: str) -> dict[str, Any] | None:
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
    predecoder = obj.get("predecoder") if isinstance(obj.get("predecoder"), dict) else {}
    full_log = obj.get("full_log") or ""
    location = obj.get("location")

    rule_id = str(rule.get("id")) if rule.get("id") is not None else None
    description = rule.get("description") or ""

    src_ip, src_port = peel_ip_port(
        data.get("srcip") or data.get("src_ip"),
        data.get("srcport") or data.get("src_port"),
    )
    dst_ip, dst_port = peel_ip_port(
        data.get("dstip") or data.get("dest_ip"),
        data.get("dstport") or data.get("dest_port"),
    )

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

    fast_sid, fast_sig = (None, None)
    if full_log and "[**]" in full_log:
        fast_sid, fast_sig = parse_fast_signature(full_log)

    if location and "suricata/fast.log" in location and full_log:
        match = SURICATA_FAST_RE.search(full_log)
        if match:
            # Decoder IPs are often "ip:port"; the raw line is the reliable copy.
            src_ip = match.group("src_ip")
            dst_ip = match.group("dst_ip")
            src_port = match.group("src_port")
            dst_port = match.group("dst_port")

    alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    raw = full_log
    if not raw and alert:
        raw = alert.get("signature") or json.dumps(data, separators=(",", ":"))

    signature = alert.get("signature") or fast_sig
    signature_id = norm_sid(alert.get("signature_id")) or fast_sid

    extras: dict[str, Any] = {
        "rule_level": rule.get("level"),
        "rule_groups": rule.get("groups"),
        "decoder": (obj.get("decoder") or {}).get("name"),
        "wazuh_id": obj.get("id"),
    }
    if signature:
        extras["signature"] = signature
    if signature_id:
        extras["signature_id"] = signature_id
    if src_port is not None:
        extras["src_port"] = str(src_port)
    if dst_port is not None:
        extras["dst_port"] = str(dst_port)

    name_candidate = predecoder.get("hostname")
    if not name_candidate and agent.get("name") not in {None, "wazuh-client"}:
        name_candidate = agent.get("name")
    host, host_name, host_ip = resolve_host(agent.get("ip"), name_candidate, full_log or raw)

    return {
        "scenario": scenario,
        "ts": ts,
        "source": "wazuh",
        "host": host,
        "host_name": host_name,
        "host_ip": host_ip,
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
    with path.open() as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSON ({exc})") from exc


def suricata_flow_key(event: dict[str, Any]) -> tuple | None:
    """One direction of one Suricata alert.

    eve.json and fast.log share this key. The reverse direction does not.
    """
    location = event.get("location") or ""
    if "suricata/" not in location:
        return None
    extras = event.get("extras") or {}
    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")
    if not src_ip or not dst_ip:
        return None
    signature = extras.get("signature_id") or extras.get("signature")
    if not signature:
        return None
    return (
        signature,
        src_ip,
        str(extras.get("src_port") or ""),
        dst_ip,
        str(extras.get("dst_port") or ""),
    )


def dedup_suricata(
    events: list[dict[str, Any]],
    window_s: float = SURICATA_DEDUP_WINDOW_S,
) -> tuple[list[dict[str, Any]], int]:
    """Drop only a repeated write of the same Suricata alert.

    Same file, same direction, same signature, timestamps within window_s.
    eve.json and fast.log are both kept: together with the other logs they
    are the ~2.66M source events. The reverse direction is a different alert.
    """
    out: list[dict[str, Any]] = []
    seen: dict[tuple, float] = {}
    dropped = 0
    for event in events:
        key = suricata_flow_key(event)
        location = event.get("location") or ""
        if key is None:
            out.append(event)
            continue
        previous = seen.get((location, key))
        if previous is not None and abs(event["ts"] - previous) <= window_s:
            dropped += 1
            continue
        seen[(location, key)] = event["ts"]
        out.append(event)
    return out, dropped


def discover_scenarios(dataset_dir: Path) -> list[tuple[str, Path | None, Path | None]]:
    found: dict[str, dict[str, Path]] = {}
    for path in sorted(dataset_dir.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        if name.endswith("_aminer.json"):
            scenario = name[: -len("_aminer.json")]
            found.setdefault(scenario, {})["aminer"] = path
        elif name.endswith("_wazuh.json"):
            scenario = name[: -len("_wazuh.json")]
            found.setdefault(scenario, {})["wazuh"] = path
    if not found:
        raise SystemExit(
            f"No <scenario>_aminer.json or <scenario>_wazuh.json files in {dataset_dir}"
        )
    return [
        (scenario, sides.get("aminer"), sides.get("wazuh"))
        for scenario, sides in sorted(found.items())
    ]


def load_scenario(
    scenario: str,
    aminer_path: Path | None,
    wazuh_path: Path | None,
    *,
    dedup: bool,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    stats = {
        "aminer_seen": 0,
        "training_dropped": 0,
        "aminer_out": 0,
        "wazuh_seen": 0,
        "wazuh_out": 0,
        "suricata_dropped": 0,
    }
    events: list[dict[str, Any]] = []

    if aminer_path is not None:
        print(f"  reading {aminer_path.name}", flush=True)
        for obj in iter_jsonl(aminer_path):
            stats["aminer_seen"] += 1
            event = normalize_aminer(obj, scenario)
            if event is None:
                if (obj.get("AnalysisComponent") or {}).get("TrainingMode") is True:
                    stats["training_dropped"] += 1
                continue
            events.append(event)
        stats["aminer_out"] = stats["aminer_seen"] - stats["training_dropped"]

    if wazuh_path is not None:
        print(f"  reading {wazuh_path.name}", flush=True)
        for obj in iter_jsonl(wazuh_path):
            stats["wazuh_seen"] += 1
            event = normalize_wazuh(obj, scenario)
            if event is not None:
                events.append(event)
        stats["wazuh_out"] = sum(1 for event in events if event["source"] == "wazuh")

    events.sort(key=lambda event: (event["ts"], event["source"], event.get("detector") or ""))
    if dedup:
        events, stats["suricata_dropped"] = dedup_suricata(events)
    return events, stats


def merge_directory(
    dataset_dir: Path,
    output: Path,
    *,
    dedup: bool = True,
) -> None:
    scenarios = discover_scenarios(dataset_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    totals = {
        "scenarios": 0,
        "events": 0,
        "aminer": 0,
        "wazuh": 0,
        "training_dropped": 0,
        "suricata_dropped": 0,
        "baseline": 0,
        "host_with_both": 0,
    }

    with output.open("w") as handle:
        for scenario, aminer_path, wazuh_path in scenarios:
            if aminer_path is None or wazuh_path is None:
                missing = "aminer" if aminer_path is None else "wazuh"
                print(f"{scenario}: missing {missing} file, merging what is present", flush=True)
            else:
                print(f"{scenario}", flush=True)
            events, stats = load_scenario(scenario, aminer_path, wazuh_path, dedup=dedup)
            for event in events:
                handle.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
                handle.write("\n")
            n_amin = sum(1 for event in events if event["source"] == "aminer")
            n_waz = sum(1 for event in events if event["source"] == "wazuh")
            n_base = sum(1 for event in events if event["is_baseline"])
            n_both = sum(
                1 for event in events if event.get("host_name") and event.get("host_ip")
            )
            totals["scenarios"] += 1
            totals["events"] += len(events)
            totals["aminer"] += n_amin
            totals["wazuh"] += n_waz
            totals["training_dropped"] += stats["training_dropped"]
            totals["suricata_dropped"] += stats["suricata_dropped"]
            totals["baseline"] += n_base
            totals["host_with_both"] += n_both
            print(
                f"  out={len(events)} aminer={n_amin} wazuh={n_waz} "
                f"training_dropped={stats['training_dropped']} "
                f"suricata_dropped={stats['suricata_dropped']}",
                flush=True,
            )

    print(
        f"Wrote {totals['events']} events ({totals['scenarios']} scenarios) -> {output}\n"
        f"  aminer={totals['aminer']} wazuh={totals['wazuh']} "
        f"baseline={totals['baseline']} host_name+ip={totals['host_with_both']}\n"
        f"  dropped training={totals['training_dropped']} "
        f"suricata_dups={totals['suricata_dropped']}",
        flush=True,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dataset_dir",
        type=Path,
        help="Folder of <scenario>_aminer.json and <scenario>_wazuh.json files",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output JSONL (default: <dataset_dir>/merged.jsonl)",
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Keep duplicate Suricata eve.json and fast.log alerts",
    )
    args = parser.parse_args(argv)

    dataset_dir = args.dataset_dir.expanduser().resolve()
    if not dataset_dir.is_dir():
        raise SystemExit(f"Not a directory: {dataset_dir}")
    output = (args.output or (dataset_dir / "merged.jsonl")).expanduser().resolve()
    if output == dataset_dir or dataset_dir in output.parents and output.parent == dataset_dir:
        # output lives beside the inputs; make sure we never overwrite a source file
        if output.name.endswith("_aminer.json") or output.name.endswith("_wazuh.json"):
            raise SystemExit(f"Refusing to overwrite an input file: {output}")
    merge_directory(dataset_dir, output, dedup=not args.no_dedup)


if __name__ == "__main__":
    main(sys.argv[1:])

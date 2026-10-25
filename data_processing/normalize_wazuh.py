
"""Normalize Wazuh JSONL logs without using Ground Truth."""
import re
import ipaddress
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def normalize_timestamp(value):
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None

def extract_ssh_src_ip(raw_log):
    """Extract SSH client IP only from recognized SSH log patterns."""
    if not isinstance(raw_log, str):
        return None

    patterns = (
        r"Received disconnect from (\d{1,3}(?:\.\d{1,3}){3})\b",
        r"Disconnected from (?:authenticating user \S+ )?(\d{1,3}(?:\.\d{1,3}){3})\b",
        r"Connection closed by (?:authenticating user \S+ )?(\d{1,3}(?:\.\d{1,3}){3})\b",
        r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})\b",
        r"Accepted \S+ for \S+ from (\d{1,3}(?:\.\d{1,3}){3})\b",
    )

    # Prevent extracting unrelated IP addresses from other log types.
    if not re.search(r"\bsshd(?:-session)?(?:\[\d+\])?:", raw_log):
        return None

    for pattern in patterns:
        match = re.search(pattern, raw_log, re.IGNORECASE)

        if match:
            candidate = match.group(1)

            try:
                address = ipaddress.ip_address(candidate)

                if isinstance(address, ipaddress.IPv4Address):
                    return str(address)

            except ValueError:
                continue

    return None

def extract_process(raw_log):
    """Extract process name from a standard syslog-style prefix."""
    if not isinstance(raw_log, str):
        return None

    pattern = (
        r"^[A-Z][a-z]{2}\s+\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2}\s+"
        r"\S+\s+"
        r"([A-Za-z0-9_.@/-]+)"
        r"(?:\[\d+\])?:"
    )

    match = re.match(pattern, raw_log)

    if match:
        return match.group(1)

    return None



def normalize_event(event, source, line_number, run_id):
    rule = event.get("rule") or {}
    agent = event.get("agent") or {}
    data = event.get("data") or {}

    if not isinstance(rule, dict):
        rule = {}
    if not isinstance(agent, dict):
        agent = {}
    if not isinstance(data, dict):
        data = {}

    source_file = f"{source}.json"

    return {
        "event_id": f"{run_id}:{source_file}:{line_number}",
        "original_event_id": (
            str(event["id"]) if event.get("id") is not None else None
        ),
        "timestamp": normalize_timestamp(event.get("timestamp")),
        "event_type": (
            "wazuh_alert" if source == "alerts"
            else "wazuh_archive"
        ),
        "src_ip": (
            data.get("srcip")
            or data.get("src_ip")
            or extract_ssh_src_ip(event.get("full_log"))
        ),
        "dst_ip": data.get("dstip") or data.get("dst_ip"),
        "user": data.get("dstuser") or data.get("srcuser"),
        "host": agent.get("name"),
        "process": extract_process(event.get("full_log")),
        "decoder_name": (
            (event.get("decoder") or {}).get("name")
            if isinstance(event.get("decoder"), dict)
            else None
        ),
        "severity": rule.get("level"),
        "severity_source": "wazuh_rule_level" if rule.get("level") is not None else None,
        "raw_log": event.get("full_log"),
        "source": "wazuh",
        "source_file": source_file,
        "source_line": line_number,
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
    }



def normalize_file(input_path, output_path, source, run_id):
    count = 0
    skipped = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open(encoding="utf-8") as src, \
         output_path.open("w", encoding="utf-8") as dst:

        for line_number, line in enumerate(src, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    skipped += 1
                    continue

                normalized = normalize_event(event, source, line_number, run_id)
                dst.write(json.dumps(normalized, ensure_ascii=False) + "\n")
                count += 1

            except json.JSONDecodeError:
                skipped += 1

    return count, skipped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    output_dir = Path(args.output_dir)

    for source in ("alerts", "archives"):
        input_path = run_dir / f"{source}.json"
        output_path = output_dir / f"wazuh_{source}.jsonl"

        if not input_path.is_file():
            print(f"{source}: SOURCE UNAVAILABLE")
            continue

        count, skipped = normalize_file(
            input_path, output_path, source, run_dir.parent.name
            if run_dir.name == "retry-01" else run_dir.name
        )
        print(f"{source}: normalized={count}, skipped={skipped}")
        print(f"output: {output_path}")


if __name__ == "__main__":
    main()

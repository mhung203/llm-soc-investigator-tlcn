
"""Normalize Wazuh JSONL logs without using Ground Truth."""

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


def normalize_event(event, source, line_number):
    rule = event.get("rule") or {}
    agent = event.get("agent") or {}
    data = event.get("data") or {}

    if not isinstance(rule, dict):
        rule = {}
    if not isinstance(agent, dict):
        agent = {}
    if not isinstance(data, dict):
        data = {}

    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dst_ip")

    # Agent IP identifies the monitored host, but is not
    # automatically assumed to be the destination in every event.
    return {
        "event_id": f"{source}:{event.get('id', line_number)}",
        "timestamp": normalize_timestamp(event.get("timestamp")),
        "event_type": "wazuh_alert" if source == "alerts" else "wazuh_archive",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": data.get("dstuser") or data.get("srcuser"),
        "host": agent.get("name"),
        "process": (event.get("decoder") or {}).get("name")
                   if isinstance(event.get("decoder"), dict) else None,
        "severity": rule.get("level"),
        "raw_log": event.get("full_log"),
        "source": "wazuh",
        "source_file": source + ".json",
        "source_line": line_number,
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
    }


def normalize_file(input_path, output_path, source):
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

                normalized = normalize_event(event, source, line_number)
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

        count, skipped = normalize_file(input_path, output_path, source)
        print(f"{source}: normalized={count}, skipped={skipped}")
        print(f"output: {output_path}")


if __name__ == "__main__":
    main()


"""Normalize Suricata EVE JSONL logs without Ground Truth."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path



def normalize_timestamp(value):
    """Convert Suricata timestamps to UTC ISO 8601."""
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    formats = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    )

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue

    return None



def normalize_event(event, line_number):
    event_type = event.get("event_type")
    alert = event.get("alert") or {}
    if not isinstance(alert, dict):
        alert = {}

    ssh = event.get("ssh") or {}
    http = event.get("http") or {}
    if not isinstance(ssh, dict):
        ssh = {}
    if not isinstance(http, dict):
        http = {}

    flow_id = event.get("flow_id")

    return {
        "event_id": f"suricata_eve:{line_number}",
        "timestamp": normalize_timestamp(event.get("timestamp")),
        "event_type": f"suricata_{event_type}" if event_type else "suricata_unknown",
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dest_ip"),
        "user": None,
        "host": None,
        "process": None,
        "severity": alert.get("severity") if event_type == "alert" else None,
        "raw_log": json.dumps(event, ensure_ascii=False),
        "source": "suricata",
        "source_file": "suricata_eve.json",
        "source_line": line_number,
        "src_port": event.get("src_port"),
        "dst_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "flow_id": flow_id,
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "http_hostname": http.get("hostname"),
        "http_url": http.get("url"),
        "ssh_proto_version": ssh.get("proto_version"),
    }


def normalize_file(input_path, output_path):
    normalized_count = 0
    skipped_count = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open(encoding="utf-8") as src, \
         output_path.open("w", encoding="utf-8") as dst:

        for line_number, line in enumerate(src, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped_count += 1
                continue

            if not isinstance(event, dict):
                skipped_count += 1
                continue

            normalized = normalize_event(event, line_number)
            dst.write(json.dumps(normalized, ensure_ascii=False) + "\n")
            normalized_count += 1

    return normalized_count, skipped_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    input_path = Path(args.run_dir) / "suricata_eve.json"
    output_path = Path(args.output_dir) / "suricata_eve.jsonl"

    if not input_path.is_file():
        print("suricata: SOURCE UNAVAILABLE")
        return

    count, skipped = normalize_file(input_path, output_path)

    print(f"suricata: normalized={count}, skipped={skipped}")
    print(f"output: {output_path}")


if __name__ == "__main__":
    main()

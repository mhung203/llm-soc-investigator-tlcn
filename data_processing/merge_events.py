
"""Merge normalized Wazuh and Suricata events by UTC timestamp."""

import argparse
import json
from datetime import datetime
from pathlib import Path


INPUT_FILES = (
    "wazuh_alerts.jsonl",
    "wazuh_archives.jsonl",
    "suricata_eve.jsonl",
)


def load_events(input_dir):
    events = []

    for filename in INPUT_FILES:
        path = input_dir / filename

        if not path.exists():
            print(f"WARNING: Missing source: {filename}")
            continue

        count = 0

        with path.open(encoding="utf-8") as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue

                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError(
                        f"{filename}:{line_number} is not a JSON object"
                    )

                timestamp = event.get("timestamp")

                if not timestamp:
                    raise ValueError(
                        f"{filename}:{line_number} missing timestamp"
                    )

                dt = datetime.fromisoformat(timestamp)

                if dt.tzinfo is None:
                    raise ValueError(
                        f"{filename}:{line_number} has no timezone"
                    )

                events.append(event)
                count += 1

        print(f"{filename}: loaded={count}")

    return events


def merge_events(input_dir, output_file):
    events = load_events(input_dir)

    events.sort(
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"TOTAL MERGED: {len(events)}")
    print(f"OUTPUT: {output_file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()

    merge_events(
        Path(args.input_dir),
        Path(args.output_file),
    )


if __name__ == "__main__":
    main()

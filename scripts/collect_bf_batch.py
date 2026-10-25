import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

BASE = Path.home() / "llm-soc/dataset/runs/brute_force"
CONTAINER = "single-node_wazuh.manager_1"
RULES = {"2502", "5503", "5557", "5760"}

def read_docker(path):
    result = subprocess.run(
        ["sudo", "docker", "exec", CONTAINER, "cat", path],
        capture_output=True, text=True, check=True
    )
    return result.stdout.splitlines()

def parse_time(value):
    try:
        return datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%S.%f%z"
        ).astimezone(timezone.utc)
    except ValueError:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc)

def load_events(lines, start, end):
    selected = []
    for line in lines:
        try:
            event = json.loads(line)
            ts = parse_time(event["timestamp"])
            if start <= ts <= end:
                selected.append(event)
        except (ValueError, KeyError, json.JSONDecodeError):
            continue
    return selected

def write_jsonl(path, events):
    with path.open("w") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

print("Đọc Wazuh alerts...")
alert_lines = read_docker("/var/ossec/logs/alerts/alerts.json")

print("Đọc Wazuh archives...")
archive_lines = read_docker("/var/ossec/logs/archives/archives.json")

print("Đọc Suricata EVE...")
suricata_lines = subprocess.run(
    ["sudo", "cat", "/var/log/suricata/eve.json"],
    capture_output=True, text=True, check=True
).stdout.splitlines()

for n in range(3, 11):
    run_id = f"BF-{n:03d}"
    folder = BASE / run_id

    start = parse_time((folder / "start_time.txt").read_text().strip())
    end = parse_time((folder / "end_time.txt").read_text().strip())

    if end < start:
        raise ValueError(f"{run_id}: end_time trước start_time")

    alerts = load_events(alert_lines, start, end)
    archives = load_events(archive_lines, start, end)
    suricata = load_events(suricata_lines, start, end)

    write_jsonl(folder / "alerts_full.json", alerts)

    filtered = [
        e for e in alerts
        if e.get("agent", {}).get("name") == "Linux-01"
        and str(e.get("rule", {}).get("id")) in RULES
    ]
    write_jsonl(folder / "alerts.json", filtered)

    write_jsonl(folder / "archives_full.json", archives)
    shutil.copyfile(
        folder / "archives_full.json",
        folder / "archives.json"
    )
    write_jsonl(folder / "suricata_eve.json", suricata)

    print(
        f"{run_id}: alerts={len(alerts)} "
        f"filtered={len(filtered)} "
        f"archives={len(archives)} "
        f"suricata={len(suricata)}"
    )

print("HOAN THANH TRICH XUAT BF-003 DEN BF-010")

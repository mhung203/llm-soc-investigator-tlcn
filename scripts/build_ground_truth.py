#!/usr/bin/env python3
import csv
import json
from pathlib import Path

BASE = Path.home() / "llm-soc/dataset"
RUNS = BASE / "runs"
OUTPUT = BASE / "ground_truth.csv"

def count_events(path):
    if not path.exists():
        return None
    with path.open() as f:
        return sum(1 for line in f if line.strip())

def load_events(path):
    if not path.exists():
        return []
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]

def read_text(path):
    return path.read_text().strip() if path.exists() else ""

rows = []

for n in range(1, 11):
    run_id = f"BF-{n:03d}"
    folder = RUNS / "brute_force" / run_id
    wazuh = load_events(folder / "alerts.json")
    suricata = load_events(folder / "suricata_eve.json")
    rules = {e.get("rule", {}).get("id") for e in wazuh}

    hydra = read_text(folder / "hydra_output.txt")
    password_result = (
        "false" if "0 valid password found" in hydra else "unknown"
    )

    rows.append({
        "run_id": run_id,
        "attack_type": "ssh_brute_force",
        "attack_present": "true",
        "attack_success": password_result,
        "source_ip": "192.168.186.185",
        "destination_ip": "192.168.186.186",
        "destination_port": 22,
        "start_time": read_text(folder / "start_time.txt"),
        "end_time": read_text(folder / "end_time.txt"),
        "wazuh_alert_count": len(wazuh),
        "wazuh_raw_count": count_events(folder / "archives.json"),
        "wazuh_auth_failure_alert": str(
            bool(rules & {"5760", "2502", "5503", "5557"})
        ).lower(),
        "suricata_event_count": count_events(folder / "suricata_eve.json"),
        "suricata_protocol_observed": str(
            any(e.get("event_type") == "ssh" for e in suricata)
        ).lower(),
        "suricata_attack_alert": str(
            any(e.get("event_type") == "alert" for e in suricata)
        ).lower(),
        "evidence_directory": str(folder),
        "notes": (
            "Manual run; Hydra result not independently available; "
            "Suricata SSH evidence missing."
            if n == 1 else
            "Manual run; Hydra result not independently available."
            if n == 2 else
            "Five incorrect password attempts; zero valid passwords found."
        ),
    })

for n in range(1, 11):
    run_id = f"EX-{n:03d}"
    folder = RUNS / "data_exfiltration" / run_id
    if n == 1:
        folder = folder / "retry-01"

    wazuh = load_events(folder / "alerts.json")
    suricata = load_events(folder / "suricata_eve.json")
    expected = f"/home/kali/exfil-lab/{run_id}.txt"
    if n == 1:
        expected = "/home/kali/exfil-lab/EX-001-retry-01.txt"

    fim_found = any(
        e.get("rule", {}).get("id") == "554"
        and e.get("syscheck", {}).get("path") == expected
        for e in wazuh
    )
    http_found = any(
        e.get("event_type") == "http"
        and e.get("http", {}).get("http_method") == "POST"
        for e in suricata
    )

    rows.append({
        "run_id": run_id,
        "attack_type": "synthetic_http_data_exfiltration",
        "attack_present": "true",
        "attack_success": "true",
        "source_ip": "192.168.186.186",
        "destination_ip": "192.168.186.185",
        "destination_port": 8080 if n == 1 else 8081,
        "start_time": read_text(folder / "start_time.txt"),
        "end_time": read_text(folder / "end_time.txt"),
        "wazuh_alert_count": len(wazuh),
        "wazuh_raw_count": count_events(folder / "archives.json"),
        "wazuh_auth_failure_alert": "false",
        "suricata_event_count": count_events(folder / "suricata_eve.json"),
        "suricata_protocol_observed": str(http_found).lower(),
        "suricata_attack_alert": "false",
        "evidence_directory": str(folder),
        "notes": (
            f"FIM file creation observed={str(fim_found).lower()}; "
            "no dedicated exfiltration detection alert. "
            + ("Retry includes earlier failed attempts."
               if n == 1 else
               "Suricata SID 2034635 is Python HTTP banner only.")
        ),
    })

if OUTPUT.exists():
    raise SystemExit(f"STOP: {OUTPUT} already exists; no overwrite.")

with OUTPUT.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print(f"Saved: {OUTPUT}")
print(f"Rows: {len(rows)}")
print("Brute Force:", sum(r["attack_type"] == "ssh_brute_force" for r in rows))
print("Data Exfiltration:", sum(r["attack_type"] == "synthetic_http_data_exfiltration" for r in rows))

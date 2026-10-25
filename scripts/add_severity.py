#!/usr/bin/env python3
import csv
import shutil
from pathlib import Path
from datetime import datetime
from collections import Counter

path = Path.home() / "llm-soc/dataset/ground_truth.csv"

with path.open(newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    fields = list(reader.fieldnames)
    rows = list(reader)

expected = {
    *(f"BF-{i:03d}" for i in range(1, 11)),
    *(f"EX-{i:03d}" for i in range(1, 11)),
}

assert len(rows) == 20, "Dataset phải có đúng 20 incident"
assert {r["run_id"] for r in rows} == expected, "Danh sách incident không hợp lệ"

for field in ("severity", "severity_reason", "severity_status"):
    if field not in fields:
        fields.append(field)

for row in rows:
    run_id = row["run_id"]

    if run_id.startswith("BF-"):
        row["severity"] = "Medium"
        if row["attack_success"].strip().lower() == "unknown":
            row["severity_reason"] = (
                "SSH Brute Force observed; attack outcome unknown"
            )
        else:
            row["severity_reason"] = (
                "SSH Brute Force observed; no confirmed account compromise"
            )
    else:
        row["severity"] = "High"
        row["severity_reason"] = (
            "Completed simulated HTTP transfer; "
            "high SOC investigation priority"
        )

    row["severity_status"] = "provisional"

backup = path.with_name(
    "ground_truth_before_severity_"
    + datetime.now().strftime("%Y%m%d_%H%M%S")
    + ".csv"
)
shutil.copy2(path, backup)

with path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("=== INCIDENT SEVERITY GROUND TRUTH ===")
print("Backup:", backup)
print("Total incidents:", len(rows))
print("Severity:", dict(Counter(r["severity"] for r in rows)))
print("Status:", dict(Counter(r["severity_status"] for r in rows)))

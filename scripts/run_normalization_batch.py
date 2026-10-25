
"""Normalize and merge Wazuh/Suricata logs for 20 incidents."""

import json
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DATASET = PROJECT / "dataset" / "runs"
OUTPUT = PROJECT / "data_processing" / "normalized"

NORMALIZE_WAZUH = PROJECT / "data_processing" / "normalize_wazuh.py"
NORMALIZE_SURICATA = PROJECT / "data_processing" / "normalize_suricata.py"
MERGE_EVENTS = PROJECT / "data_processing" / "merge_events.py"

LOG_FILES = ("alerts.json", "archives.json", "suricata_eve.json")


def get_input_directory(group, run_id):
    base = DATASET / group / run_id

    # EX-001's validated experiment is in retry-01.
    if run_id == "EX-001":
        return base / "retry-01"

    return base


def run_script(script, arguments):
    command = [sys.executable, str(script), *arguments]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr)
        raise RuntimeError(
            f"Failed: {script.name}, exit={result.returncode}"
        )

    return result.stdout.strip()


def count_jsonl(path):
    with path.open(encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def process_incident(group, run_id):
    source = get_input_directory(group, run_id)
    destination = OUTPUT / run_id

    if not source.is_dir():
        raise FileNotFoundError(f"Incident directory not found: {source}")

    # The two Wazuh sources must be present.
    for name in ("alerts.json", "archives.json"):
        if not (source / name).is_file():
            raise FileNotFoundError(f"Required source missing: {source / name}")

    destination.mkdir(parents=True, exist_ok=True)

    run_script(
        NORMALIZE_WAZUH,
        ["--run-dir", str(source), "--output-dir", str(destination)],
    )

    suricata_available = (source / "suricata_eve.json").is_file()

    if suricata_available:
        run_script(
            NORMALIZE_SURICATA,
            ["--run-dir", str(source), "--output-dir", str(destination)],
        )
    else:
        # Avoid reusing a stale Suricata output from an earlier run.
        old = destination / "suricata_eve.jsonl"
        if old.exists():
            old.unlink()

    merged_file = destination / "merged_events.jsonl"

    run_script(
        MERGE_EVENTS,
        [
            "--input-dir", str(destination),
            "--output-file", str(merged_file),
        ],
    )

    counts = {
        "wazuh_alerts": count_jsonl(destination / "wazuh_alerts.jsonl"),
        "wazuh_archives": count_jsonl(destination / "wazuh_archives.jsonl"),
        "suricata": (
            count_jsonl(destination / "suricata_eve.jsonl")
            if suricata_available else None
        ),
    }

    expected = sum(value for value in counts.values() if value is not None)
    merged = count_jsonl(merged_file)

    if merged != expected:
        raise ValueError(
            f"{run_id}: expected {expected} events, got {merged}"
        )

    return {
        "run_id": run_id,
        "input_directory": str(source.relative_to(PROJECT)),
        "suricata_status": (
            "available" if suricata_available else "source_unavailable"
        ),
        "counts": counts,
        "merged_count": merged,
        "status": "PASS",
    }


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    results = []
    failures = []

    print("=== TASK 2.1.26 - BATCH NORMALIZATION ===")

    for group, prefix in (
        ("brute_force", "BF"),
        ("data_exfiltration", "EX"),
    ):
        for number in range(1, 11):
            run_id = f"{prefix}-{number:03d}"

            try:
                result = process_incident(group, run_id)
                results.append(result)

                print(
                    f"{run_id}: PASS | "
                    f"merged={result['merged_count']} | "
                    f"suricata={result['suricata_status']}"
                )
            except Exception as exc:
                failures.append({
                    "run_id": run_id,
                    "error": str(exc),
                })
                print(f"{run_id}: FAIL | {exc}")

    summary = {
        "total_incidents": 20,
        "passed": len(results),
        "failed": len(failures),
        "total_merged_events": sum(
            item["merged_count"] for item in results
        ),
        "results": results,
        "failures": failures,
    }

    report = OUTPUT / "batch_summary.json"
    report.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== BATCH SUMMARY ===")
    print(f"PASSED: {len(results)}/20")
    print(f"FAILED: {len(failures)}")
    print(f"TOTAL MERGED EVENTS: {summary['total_merged_events']}")
    print(f"REPORT: {report}")

    if failures:
        sys.exit(1)

    print("BATCH NORMALIZATION: PASS")


if __name__ == "__main__":
    main()

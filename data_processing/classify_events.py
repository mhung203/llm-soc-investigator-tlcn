
"""Classify normalized SOC events without Ground Truth labels."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path


def matches(pattern, value):
    return bool(re.search(pattern, value, re.IGNORECASE))


def classify_wazuh(event):
    raw = event.get("raw_log") or ""
    decoder = event.get("decoder_name")

    # File Integrity Monitoring events.
    if decoder == "syscheck_new_entry" and matches(
        r"^File '.*' added\b", raw
    ):
        return "file_created"

    if decoder == "syscheck_integrity_changed" and matches(
        r"^File '.*' modified\b", raw
    ):
        return "file_modified"

    # Explicit SSH authentication events.
    if matches(
        r"\bAccepted (?:password|publickey|keyboard-interactive)\b",
        raw
    ) and matches(r"\bsshd(?:-session)?(?:\[\d+\])?:", raw):
        return "ssh_auth_success"

    if (
        matches(r"\bFailed password for\b", raw)
        or matches(
            r"pam_unix\(sshd:auth\).*authentication failure",
            raw
        )
    ):
        return "ssh_auth_failure"

    # PAM summary: do not count as independent failed attempts.
    if matches(
        r"\bPAM \d+ more authentication failures\b", raw
    ) and matches(r"\bsshd(?:-session)?(?:\[\d+\])?:", raw):
        return "ssh_auth_failure_summary"

    # PAM SSH maximum retry threshold.
    if matches(
        r"\bPAM service\(sshd\) ignoring max retries\b", raw
    ):
        return "ssh_max_retries_exceeded"

    # SSH session lifecycle, not evidence of attack by itself.
    if matches(
        r"pam_unix\(sshd:session\): session opened for user\b", raw
    ):
        return "ssh_session_opened"

    if matches(
        r"pam_unix\(sshd:session\): session closed for user\b", raw
    ):
        return "ssh_session_closed"

    # Password checker alone does not prove a Brute Force attack.
    if decoder == "unix_chkpwd" and matches(
        r"\bpassword check failed for user\b", raw
    ):
        return "password_check_failure"

    if matches(
        r"\b(?:Received disconnect from|Disconnected from|"
        r"Connection closed by)\b",
        raw
    ) and matches(r"\bsshd(?:-session)?(?:\[\d+\])?:", raw):
        return "ssh_disconnect"

    return "other"


def classify_suricata(event):
    raw = event.get("raw_log") or ""

    try:
        original = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return "other"

    event_type = original.get("event_type")
    http = original.get("http") or {}

    if not isinstance(http, dict):
        http = {}

    method = str(http.get("http_method") or "").upper()

    if event_type == "http" and method == "POST":
        return "http_post"

    if event_type == "fileinfo" and method == "POST":
        return "http_file_transfer"

    if event_type == "alert":
        if method == "POST":
            return "http_post_context_alert"
        return "informational_alert"

    if event_type == "ssh":
        return "ssh_network_activity"

    if event_type == "flow":
        return "network_flow"

    if event_type == "stats":
        return "sensor_statistics"

    return "other"


def classify_event(event):
    source = event.get("source")

    if source == "wazuh":
        return classify_wazuh(event)

    if source == "suricata":
        return classify_suricata(event)

    return "other"


def process_file(input_path, output_path):
    counts = Counter()
    total = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open(encoding="utf-8") as src, \
         output_path.open("w", encoding="utf-8") as dst:

        for line_number, line in enumerate(src, 1):
            if not line.strip():
                continue

            event = json.loads(line)

            if not isinstance(event, dict):
                raise ValueError(
                    f"Line {line_number}: not a JSON object"
                )

            # Keep original event_type and all evidence fields.
            event["security_event_type"] = classify_event(event)

            dst.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

            counts[event["security_event_type"]] += 1
            total += 1

    print("TOTAL CLASSIFIED:", total)
    print("SECURITY EVENT TYPE DISTRIBUTION:")

    for name, count in sorted(counts.items()):
        print(f"  {name}: {count}")

    print("OUTPUT:", output_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()

    process_file(
        Path(args.input_file),
        Path(args.output_file)
    )


if __name__ == "__main__":
    main()

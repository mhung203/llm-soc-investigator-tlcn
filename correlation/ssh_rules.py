"""SSH correlation rules migrated from verified Gantt 2.6 modules."""

import json

from collections import Counter, defaultdict

from datetime import datetime

from pathlib import Path

from correlation.common import extract_context, deduplicate_wazuh

ADDITIONAL_TYPES = {
    "ssh_auth_failure_summary",
    "ssh_max_retries_exceeded",
}

def correlate_ssh_process_aware(events, window_seconds=30):
    failures = [
        e for e in events
        if e.get("source") == "wazuh"
        and e.get("security_event_type") == "ssh_auth_failure"
    ]

    unique = deduplicate_wazuh(failures)
    process_buckets = defaultdict(list)
    ungrouped = []

    for evidence in unique:
        pid = extract_context(evidence).get("sshd_pid")
        src_ip = evidence.get("src_ip")
        agent_ip = evidence.get("agent_ip")
        user = evidence.get("user")

        if not all((pid, src_ip, agent_ip, user)):
            ungrouped.append(evidence["event_id"])
            continue

        process_key = (agent_ip, pid, src_ip, user)
        process_buckets[process_key].append(evidence)

    processes_by_activity_key = defaultdict(list)

    for (agent_ip, pid, src_ip, user), members in process_buckets.items():
        members.sort(key=lambda e: (e["timestamp"], e["event_id"]))

        process = {
            "sshd_pid": pid,
            "start_time": members[0]["timestamp"],
            "end_time": members[-1]["timestamp"],
            "unique_failure_evidence": len(members),
            "evidence": [
                {
                    "event_id": e["event_id"],
                    "event_ids": e["event_ids"],
                    "timestamp": e["timestamp"],
                }
                for e in members
            ],
        }

        processes_by_activity_key[
            (src_ip, agent_ip, user)
        ].append(process)

    activities = []

    for (src_ip, agent_ip, user), processes in sorted(
        processes_by_activity_key.items()
    ):
        processes.sort(
            key=lambda p: (p["start_time"], p["sshd_pid"])
        )

        current = []
        anchor_time = None

        def emit(group):
            if not group:
                return

            activities.append({
                "src_ip": src_ip,
                "agent_ip": agent_ip,
                "user": user,
                "start_time": min(p["start_time"] for p in group),
                "end_time": max(p["end_time"] for p in group),
                "sshd_pids": [p["sshd_pid"] for p in group],
                "unique_failure_evidence": sum(
                    p["unique_failure_evidence"] for p in group
                ),
                "process_groups": list(group),
            })

        for process in processes:
            start = datetime.fromisoformat(process["start_time"])

            if anchor_time is None:
                anchor_time = start

            elif (start - anchor_time).total_seconds() > window_seconds:
                emit(current)
                current = []
                anchor_time = start

            current.append(process)

        emit(current)

    activities.sort(
        key=lambda a: (
            a["start_time"], a["src_ip"],
            a["agent_ip"], a["user"]
        )
    )

    return {
        "groups": activities,
        "ungrouped_missing_keys": ungrouped,
    }

def correlate_ssh_supporting(events, threshold_seconds=5):
    """Return links to SSH processes without inferring missing IPs or PIDs."""
    bf_result = correlate_ssh_process_aware(events)

    process_index = []

    for activity in bf_result["groups"]:
        for process in activity["process_groups"]:
            process_index.append({
                "agent_ip": activity["agent_ip"],
                "user": activity["user"],
                "src_ip": activity["src_ip"],
                "sshd_pid": process["sshd_pid"],
                "failure_timestamps": [
                    datetime.fromisoformat(e["timestamp"])
                    for e in process["evidence"]
                ],
            })

    password_records = [
        e for e in events
        if e.get("source") == "wazuh"
        and e.get("security_event_type") == "password_check_failure"
    ]

    unique_checks = deduplicate_wazuh(password_records)

    linked = []
    unresolved = []

    for check in unique_checks:
        check_time = datetime.fromisoformat(check["timestamp"])
        candidates = []

        for process in process_index:
            if (
                process["agent_ip"] != check.get("agent_ip")
                or process["user"] != check.get("user")
            ):
                continue

            gap = min(
                abs((timestamp - check_time).total_seconds())
                for timestamp in process["failure_timestamps"]
            )

            if gap <= threshold_seconds:
                candidates.append((gap, process))

        base = {
            "event_ids": list(check["event_ids"]),
            "timestamp": check["timestamp"],
            "agent_ip": check.get("agent_ip"),
            "user": check.get("user"),
            "security_event_type": "password_check_failure",
        }

        if len(candidates) == 1:
            gap, process = candidates[0]

            linked.append({
                **base,
                "linked_process": {
                    "agent_ip": process["agent_ip"],
                    "sshd_pid": process["sshd_pid"],
                    "src_ip": process["src_ip"],
                    "user": process["user"],
                },
                "gap_seconds": round(gap, 6),
                "link_basis": "host_user_temporal_proximity",
                "link_confidence": "temporal_support_only",
            })
        else:
            unresolved.append({
                **base,
                "reason": (
                    "no_process_candidate"
                    if not candidates
                    else "multiple_process_candidates"
                ),
                "candidate_count": len(candidates),
            })

    linked.sort(key=lambda e: (e["timestamp"], e["event_ids"]))
    unresolved.sort(key=lambda e: (e["timestamp"], e["event_ids"]))

    original_ids = sorted(e["event_id"] for e in password_records)
    output_ids = sorted(
        event_id
        for item in linked + unresolved
        for event_id in item["event_ids"]
    )

    assert original_ids == output_ids, (
        "Password-check evidence lost or duplicated"
    )

    return {
        "ssh_activity_groups": bf_result["groups"],
        "linked_password_evidence": linked,
        "unresolved_password_evidence": unresolved,
        "ungrouped_ssh_failures": bf_result["ungrouped_missing_keys"],
        "threshold_seconds": threshold_seconds,
    }

def correlate_ssh_additional(events):
    """Attach context without increasing authentication failure counts."""
    bf_result = correlate_ssh_process_aware(events)

    process_index = defaultdict(list)

    for activity in bf_result["groups"]:
        for process in activity["process_groups"]:
            key = (activity["agent_ip"], process["sshd_pid"])
            process_index[key].append({
                "src_ip": activity["src_ip"],
                "user": activity["user"],
            })

    selected = [
        event for event in events
        if event.get("source") == "wazuh"
        and event.get("security_event_type") in ADDITIONAL_TYPES
    ]

    unique = deduplicate_wazuh(selected)

    linked = []
    unresolved = []

    for event in unique:
        pid = extract_context(event).get("sshd_pid")
        key = (event.get("agent_ip"), pid)

        candidates = process_index.get(key, []) if pid else []

        evidence = {
            "event_ids": list(event["event_ids"]),
            "timestamp": event["timestamp"],
            "security_event_type": event["security_event_type"],
            "agent_ip": event.get("agent_ip"),
            "sshd_pid": pid,
        }

        if len(candidates) == 1:
            linked.append({
                **evidence,
                "link_status": "process_matched",
                "link_basis": "agent_ip_and_sshd_pid",
                "linked_process": {
                    "agent_ip": key[0],
                    "sshd_pid": key[1],
                },
                "count_as_new_auth_failure": False,
            })
        else:
            unresolved.append({
                **evidence,
                "reason": (
                    "missing_ssh_pid"
                    if pid is None
                    else "no_matching_process"
                    if not candidates
                    else "multiple_matching_processes"
                ),
            })

    linked.sort(key=lambda e: (e["timestamp"], e["event_ids"]))
    unresolved.sort(key=lambda e: (e["timestamp"], e["event_ids"]))

    source_ids = sorted(e["event_id"] for e in selected)
    output_ids = sorted(
        event_id
        for evidence in linked + unresolved
        for event_id in evidence["event_ids"]
    )

    assert source_ids == output_ids, (
        "Additional SSH evidence lost or duplicated"
    )

    return {
        "ssh_activity_groups": bf_result["groups"],
        "linked_additional_evidence": linked,
        "unresolved_additional_evidence": unresolved,
    }

def correlate_ssh_disconnect(events):
    """Attach disconnects only by exact agent_ip + sshd_pid.

    Unmatched disconnects remain available as session context.
    """

    bf_result = correlate_ssh_process_aware(events)

    process_keys = {
        (activity["agent_ip"], str(process["sshd_pid"]))
        for activity in bf_result["groups"]
        for process in activity["process_groups"]
    }

    selected = [
        e for e in events
        if e.get("source") == "wazuh"
        and e.get("security_event_type") == "ssh_disconnect"
    ]

    unique = deduplicate_wazuh(selected)
    linked = []
    unmatched = []

    for event in unique:
        pid = extract_context(event).get("sshd_pid")

        evidence = {
            "event_ids": list(event["event_ids"]),
            "timestamp": event["timestamp"],
            "security_event_type": "ssh_disconnect",
            "agent_ip": event.get("agent_ip"),
            "src_ip": event.get("src_ip"),
            "user": event.get("user"),
            "sshd_pid": pid,
            "raw_log": event.get("raw_log"),
            "count_as_new_auth_failure": False,
        }

        if (
            pid is not None
            and (event.get("agent_ip"), str(pid)) in process_keys
        ):
            linked.append({
                **evidence,
                "link_status": "process_matched",
                "link_basis": "agent_ip_and_sshd_pid",
            })
        else:
            unmatched.append({
                **evidence,
                "link_status": "unmatched_session_context",
                "reason": (
                    "missing_ssh_pid"
                    if pid is None
                    else "no_matching_ssh_process"
                ),
            })

    linked.sort(key=lambda e: (e["timestamp"], e["event_ids"]))
    unmatched.sort(key=lambda e: (e["timestamp"], e["event_ids"]))

    source_ids = sorted(e["event_id"] for e in selected)
    output_ids = sorted(
        event_id
        for item in linked + unmatched
        for event_id in item["event_ids"]
    )

    assert source_ids == output_ids, (
        "SSH disconnect evidence lost or duplicated"
    )

    return {
        "linked_disconnect_evidence": linked,
        "unmatched_disconnect_evidence": unmatched,
    }


def correlate_ssh(events, supporting_window_seconds=5):
    """Run all SSH rules and return unified evidence categories."""
    primary = correlate_ssh_process_aware(
        events, window_seconds=30
    )
    password = correlate_ssh_supporting(
        events, threshold_seconds=supporting_window_seconds
    )
    additional = correlate_ssh_additional(events)
    disconnect = correlate_ssh_disconnect(events)

    return {
        "activity_groups": primary["groups"],
        "ungrouped_ssh_failures": primary["ungrouped_missing_keys"],
        "password_evidence": {
            "linked": password["linked_password_evidence"],
            "unresolved": password["unresolved_password_evidence"],
        },
        "additional_evidence": {
            "linked": additional["linked_additional_evidence"],
            "unresolved": additional["unresolved_additional_evidence"],
        },
        "disconnect_evidence": {
            "linked": disconnect["linked_disconnect_evidence"],
            "unresolved": disconnect["unmatched_disconnect_evidence"],
        },
    }


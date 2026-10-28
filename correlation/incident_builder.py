
"""Build explainable incident groups from frozen correlation results."""

import hashlib
import json
from datetime import datetime


def build_ssh_incidents(result):
    if result.get("scenario") != "ssh_brute_force":
        raise ValueError("Expected SSH correlation result")

    groups = result["activity_groups"]
    incidents = []
    process_to_group = {}

    # Index processes without using experiment run identifiers.
    for index, group in enumerate(groups):
        for process in group["process_groups"]:
            key = (group["agent_ip"], str(process["sshd_pid"]))
            if key in process_to_group:
                raise ValueError("Ambiguous SSH process across activity groups")
            process_to_group[key] = index

    timelines = [[] for _ in groups]

    def add(index, timestamp, event_type, role, ids,
            pid=None, basis=None):
        ids = sorted(set(ids))
        if not ids:
            raise ValueError("Evidence has no source event IDs")

        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            raise ValueError("Timestamp without timezone")

        timelines[index].append({
            "timestamp": timestamp,
            "security_event_type": event_type,
            "role": role,
            "event_ids": ids,
            "sshd_pid": str(pid) if pid is not None else None,
            "direction": None,
            "link_basis": basis,
        })

    for index, group in enumerate(groups):
        for process in group["process_groups"]:
            for evidence in process["evidence"]:
                add(
                    index,
                    evidence["timestamp"],
                    "ssh_auth_failure",
                    "primary",
                    evidence["event_ids"],
                    process["sshd_pid"],
                    "agent_ip_sshd_pid_src_ip_user",
                )

    categories = (
        ("password_evidence", "linked", "password_check_failure"),
        ("additional_evidence", "linked", None),
        ("disconnect_evidence", "linked", "ssh_disconnect"),
    )

    for category, status, default_type in categories:
        for evidence in result[category][status]:
            process = evidence.get("linked_process") or {}
            agent_ip = process.get("agent_ip", evidence.get("agent_ip"))
            pid = process.get("sshd_pid", evidence.get("sshd_pid"))

            key = (agent_ip, str(pid))
            if key not in process_to_group:
                raise ValueError(
                    "Supporting evidence refers to an unknown SSH process"
                )

            index = process_to_group[key]
            add(
                index,
                evidence["timestamp"],
                default_type or evidence["security_event_type"],
                "supporting",
                evidence["event_ids"],
                pid,
                evidence.get("link_basis", "agent_ip_and_sshd_pid"),
            )

    for index, group in enumerate(groups):
        timeline = sorted(
            timelines[index],
            key=lambda e: (
                datetime.fromisoformat(e["timestamp"]),
                e["security_event_type"],
                e["event_ids"],
            ),
        )

        if not timeline:
            raise ValueError("Empty incident timeline")

        ids = [
            event_id
            for item in timeline
            for event_id in item["event_ids"]
        ]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate source event across timeline")

        start = timeline[0]["timestamp"]
        end = timeline[-1]["timestamp"]
        pids = sorted(
            str(p["sshd_pid"]) for p in group["process_groups"]
        )

        identity = {
            "scenario": "ssh_brute_force",
            "src_ip": group["src_ip"],
            "agent_ip": group["agent_ip"],
            "user": group["user"],
            "start_time": group["start_time"],
            "sshd_pids": pids,
        }

        digest = hashlib.sha256(
            json.dumps(
                identity, sort_keys=True,
                separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()[:16]

        limitations = [
            "Failure log evidence is not necessarily one-to-one "
            "with authentication attempts.",
            "Supporting PAM links indicate temporal proximity, "
            "not proven causal identity.",
        ]

        if len(pids) > 1:
            limitations.append(
                "Multiple SSH processes share this activity group; "
                "they may represent separate real-world incidents."
            )

        incidents.append({
            "incident_id": "INC-BF-" + digest,
            "scenario": "ssh_brute_force",
            "start_time": start,
            "end_time": end,
            "entities": {
                "src_ip": group["src_ip"],
                "dst_ip": group["agent_ip"],
                "user": group["user"],
                "sshd_pids": pids,
                "flow_id": None,
                "http_url": None,
            },
            "timeline": timeline,
            "evidence_event_ids": sorted(ids),
            "correlation_explanation": (
                "SSH authentication failures grouped by source IP, "
                "target agent, user and SSHD process; processes "
                "correlated within a 30-second activity window. "
                "Supporting context linked by explicit process keys "
                "or unique time-proximity candidates."
            ),
            "limitations": limitations,
        })

    incidents.sort(
        key=lambda item: (
            item["start_time"], item["incident_id"]
        )
    )

    unresolved = []
    for category in (
        "password_evidence",
        "additional_evidence",
        "disconnect_evidence",
    ):
        for evidence in result[category]["unresolved"]:
            unresolved.append({
                "category": category,
                "reason": evidence["reason"],
                "event_ids": sorted(evidence["event_ids"]),
                "timestamp": evidence["timestamp"],
            })

    for event_id in result["ungrouped_ssh_failures"]:
        unresolved.append({
            "category": "ssh_auth_failure",
            "reason": "missing_correlation_keys",
            "event_ids": [event_id],
            "timestamp": None,
        })

    unresolved.sort(
        key=lambda item: (
            item["timestamp"] or "",
            item["category"],
            item["event_ids"],
        )
    )

    return {
        "incidents": incidents,
        "unresolved_evidence": unresolved,
    }

def build_http_incidents(result):
    """Convert correlated HTTP flows into explainable incident timelines."""
    if result.get("scenario") != "http_data_exfiltration":
        raise ValueError("Expected HTTP correlation result")

    incidents = []
    unresolved = []

    for flow in result["http_flows"]:
        flow_id = str(flow["flow_id"])
        post_id = flow["post_event_id"]

        post_matches = [
            e for e in flow["evidence"]
            if e["event_id"] == post_id
            and e["security_event_type"] == "http_post"
        ]
        if len(post_matches) != 1:
            raise ValueError("HTTP flow lacks exactly one POST anchor")

        post_time = post_matches[0]["timestamp"]
        timeline = []

        def add(timestamp, event_type, role, ids,
                direction=None, basis=None):
            ids = sorted(set(ids))
            if not ids:
                raise ValueError("Evidence without source IDs")
            parsed = datetime.fromisoformat(timestamp)
            if parsed.tzinfo is None:
                raise ValueError("Timestamp without timezone")

            timeline.append({
                "timestamp": timestamp,
                "security_event_type": event_type,
                "role": role,
                "event_ids": ids,
                "sshd_pid": None,
                "direction": direction,
                "link_basis": basis,
            })

        for evidence in flow["evidence"]:
            event_type = evidence["security_event_type"]
            add(
                evidence["timestamp"],
                event_type,
                "primary" if event_type == "http_post"
                else "supporting",
                [evidence["event_id"]],
                evidence.get("direction", "unknown"),
                "flow_id_and_post_anchor",
            )

        for fim in flow.get("fim_activities", []):
            add(
                fim["timestamp"],
                fim["security_event_type"],
                "supporting",
                fim["event_ids"],
                None,
                "same_agent_ip_and_pre_post_60_seconds",
            )

        timeline.sort(key=lambda e: (
            datetime.fromisoformat(e["timestamp"]),
            e["security_event_type"],
            e["event_ids"],
        ))

        ids = [
            event_id for item in timeline
            for event_id in item["event_ids"]
        ]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate source ID inside HTTP incident")

        identity = {
            "scenario": "http_data_exfiltration",
            "flow_id": flow_id,
            "request_src_ip": flow["request_src_ip"],
            "request_src_port": str(flow["request_src_port"]),
            "request_dst_ip": flow["request_dst_ip"],
            "request_dst_port": str(flow["request_dst_port"]),
            "post_time": post_time,
        }

        digest = hashlib.sha256(
            json.dumps(
                identity, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()[:16]

        limitations = [
            "HTTP POST and related Suricata evidence do not by "
            "themselves prove confidential data exfiltration."
        ]

        if flow["fim_link_status"] == "matched":
            limitations.append(
                "FIM is linked by host and temporal proximity; "
                "file-content identity and successful transfer "
                "are not independently verified."
            )
        else:
            limitations.append(
                "No FIM activity satisfied the configured "
                "60-second correlation rule."
            )

        incidents.append({
            "incident_id": "INC-EX-" + digest,
            "scenario": "http_data_exfiltration",
            "start_time": timeline[0]["timestamp"],
            "end_time": timeline[-1]["timestamp"],
            "entities": {
                "src_ip": flow["request_src_ip"],
                "dst_ip": flow["request_dst_ip"],
                "user": None,
                "sshd_pids": [],
                "flow_id": flow_id,
                "http_url": flow.get("http_url"),
            },
            "timeline": timeline,
            "evidence_event_ids": sorted(ids),
            "correlation_explanation": (
                "Suricata HTTP records grouped by flow_id "
                "with one HTTP POST anchor. Request and response "
                "directions are determined relative to POST. "
                "Wazuh FIM is attached only when its host and "
                "timestamp meet the configured 60-second rule. "
                "FIM link status: " + flow["fim_link_status"]
            ),
            "limitations": limitations,
        })

    for evidence in result["unresolved_http_evidence"]:
        unresolved.append({
            "category": evidence["security_event_type"],
            "reason": evidence["reason"],
            "event_ids": [evidence["event_id"]],
            "timestamp": evidence.get("timestamp"),
        })

    incidents.sort(key=lambda i: (
        datetime.fromisoformat(i["start_time"]),
        i["incident_id"],
    ))
    unresolved.sort(key=lambda e: (
        e["timestamp"] or "",
        e["category"],
        e["event_ids"],
    ))

    if len({i["incident_id"] for i in incidents}) != len(incidents):
        raise ValueError("Duplicate HTTP incident IDs")

    return {
        "incidents": incidents,
        "unresolved_evidence": unresolved,
    }

"""Shared correlation utilities extracted from tested modules."""

import json

import re

from collections import defaultdict

SSH_PID_PATTERN = re.compile(
    r"\bsshd(?:-session)?\[(\d+)\]:"
)

def extract_context(event):
    """Extract correlation context without modifying the input event."""
    context = {
        "event_id": event["event_id"],
        "security_event_type": event.get("security_event_type"),
        "sshd_pid": None,
        "http_method": None,
        "http_file_size": None,
        "http_direction": None,
    }

    source = event.get("source")

    if source == "wazuh":
        raw_log = event.get("raw_log") or ""
        match = SSH_PID_PATTERN.search(raw_log)

        if match:
            context["sshd_pid"] = match.group(1)

    elif source == "suricata":
        raw = json.loads(event.get("raw_log") or "{}")
        http = raw.get("http") or {}
        fileinfo = raw.get("fileinfo") or {}

        context["http_method"] = http.get("http_method")
        context["http_file_size"] = fileinfo.get("size")

        # Direction is resolved later using the HTTP POST event
        # as the request anchor for the same flow_id.
        context["http_direction"] = None

    return context

def deduplicate_wazuh(events):
    """Return logical Wazuh evidence and preserve source references."""
    buckets = defaultdict(list)

    for event in events:
        if event.get("source") != "wazuh":
            continue

        key = (
            event.get("agent_ip"),
            event.get("timestamp"),
            event.get("raw_log"),
            event.get("security_event_type"),
        )

        buckets[key].append(event)

    results = []

    for members in buckets.values():
        members = sorted(
            members,
            key=lambda e: e["event_id"]
        )

        representative = members[0]

        results.append({
            "event_id": representative["event_id"],
            "source": representative["source"],
            "event_ids": [e["event_id"] for e in members],
            "timestamp": representative.get("timestamp"),
            "security_event_type": representative.get(
                "security_event_type"
            ),
            "agent_ip": representative.get("agent_ip"),
            "src_ip": representative.get("src_ip"),
            "user": representative.get("user"),
            "raw_log": representative.get("raw_log"),
            "duplicate_count": len(members) - 1,
        })

    return sorted(
        results,
        key=lambda e: (e["timestamp"], e["event_id"])
    )

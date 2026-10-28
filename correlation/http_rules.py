"""HTTP correlation rules migrated from verified Gantt 2.6 modules."""

import json

from collections import defaultdict

from datetime import datetime

from pathlib import Path

HTTP_TYPES = {
    "http_post",
    "http_file_transfer",
    "http_post_context_alert",
}

FIM_TYPES = {"file_created", "file_modified"}

def correlate_http_flows(events):
    """Build HTTP flow groups without using run_id or Ground Truth."""
    buckets = defaultdict(list)

    for event in events:
        if event.get("source") != "suricata":
            continue
        if event.get("security_event_type") not in HTTP_TYPES:
            continue

        flow_id = event.get("flow_id")
        if flow_id is None:
            continue

        buckets[str(flow_id)].append(event)

    results = []

    for flow_id, members in sorted(buckets.items()):
        posts = [
            e for e in members
            if e.get("security_event_type") == "http_post"
            and e.get("src_ip")
            and e.get("dst_ip")
            and e.get("src_port") is not None
            and e.get("dst_port") is not None
        ]

        # A unique POST anchors the connection direction.
        # Ambiguous flows must not be assigned an arbitrary direction.
        if len(posts) != 1:
            continue

        anchor = posts[0]

        request_endpoint = (
            anchor["src_ip"],
            anchor["src_port"],
            anchor["dst_ip"],
            anchor["dst_port"],
        )

        response_endpoint = (
            anchor["dst_ip"],
            anchor["dst_port"],
            anchor["src_ip"],
            anchor["src_port"],
        )

        evidence = []

        for event in sorted(
            members,
            key=lambda e: (e["timestamp"], e["event_id"])
        ):
            endpoint = (
                event.get("src_ip"),
                event.get("src_port"),
                event.get("dst_ip"),
                event.get("dst_port"),
            )

            if endpoint == request_endpoint:
                direction = "request"
            elif endpoint == response_endpoint:
                direction = "response"
            else:
                direction = "unknown"

            evidence.append({
                "event_id": event["event_id"],
                "security_event_type": event["security_event_type"],
                "timestamp": event["timestamp"],
                "direction": direction,
            })

        results.append({
            "flow_id": flow_id,
            "request_src_ip": anchor["src_ip"],
            "request_src_port": anchor["src_port"],
            "request_dst_ip": anchor["dst_ip"],
            "request_dst_port": anchor["dst_port"],
            "http_url": anchor.get("http_url"),
            "post_event_id": anchor["event_id"],
            "evidence": evidence,
        })

    return results

def correlate_fim_http(events, window_seconds=60):
    """Link FIM records to HTTP flows using host and time evidence."""
    flows = correlate_http_flows(events)

    fim_events = [
        event for event in events
        if event.get("source") == "wazuh"
        and event.get("security_event_type") in FIM_TYPES
    ]

    results = []

    for flow in flows:
        post = next(
            event for event in events
            if event["event_id"] == flow["post_event_id"]
        )

        post_time = datetime.fromisoformat(post["timestamp"])
        matched = []

        for fim in fim_events:
            if not fim.get("agent_ip"):
                continue

            if fim["agent_ip"] != flow["request_src_ip"]:
                continue

            fim_time = datetime.fromisoformat(fim["timestamp"])
            gap = (post_time - fim_time).total_seconds()

            if not 0 <= gap <= window_seconds:
                continue

            matched.append({
                "event_id": fim["event_id"],
                "security_event_type": fim["security_event_type"],
                "timestamp": fim["timestamp"],
                "gap_seconds": round(gap, 6),
            })

        # Alerts and Archives can describe one FIM activity.
        # Preserve source event IDs, but avoid treating identical
        # activity descriptions at identical timestamps as independent.
        activities = {}

        for evidence in matched:
            source_event = next(
                e for e in fim_events
                if e["event_id"] == evidence["event_id"]
            )

            activity_key = (
                evidence["timestamp"],
                evidence["security_event_type"],
                source_event.get("agent_ip"),
                source_event.get("raw_log"),
            )

            if activity_key not in activities:
                activities[activity_key] = {
                    "timestamp": evidence["timestamp"],
                    "security_event_type": evidence["security_event_type"],
                    "gap_seconds": evidence["gap_seconds"],
                    "event_ids": [],
                }

            activities[activity_key]["event_ids"].append(
                evidence["event_id"]
            )

        results.append({
            **flow,
            "fim_activities": sorted(
                activities.values(),
                key=lambda x: (x["timestamp"], x["event_ids"])
            ),
            "fim_link_status": (
                "matched" if activities else "unmatched"
            ),
        })

    # Canonicalize duplicate Wazuh source IDs.
    for flow in results:
        for activity in flow.get('fim_activities', []):
            activity['event_ids'].sort()

    return results

def correlate_http_with_audit(events):
    """Return resolved flows and evidence that could not be linked."""
    resolved = correlate_http_flows(events)

    selected = [
        e for e in events
        if e.get("source") == "suricata"
        and e.get("security_event_type") in HTTP_TYPES
    ]

    linked_ids = {
        item["event_id"]
        for flow in resolved
        for item in flow["evidence"]
    }

    buckets = defaultdict(list)

    for event in selected:
        flow_id = event.get("flow_id")
        if flow_id is not None:
            buckets[str(flow_id)].append(event)

    unresolved = []

    for event in selected:
        if event["event_id"] in linked_ids:
            continue

        flow_id = event.get("flow_id")

        if flow_id is None:
            reason = "missing_flow_id"
        else:
            members = buckets[str(flow_id)]
            posts = [
                e for e in members
                if e.get("security_event_type") == "http_post"
            ]

            valid_posts = [
                e for e in posts
                if e.get("src_ip")
                and e.get("dst_ip")
                and e.get("src_port") is not None
                and e.get("dst_port") is not None
            ]

            if len(posts) == 0:
                reason = "missing_post_anchor"
            elif len(posts) > 1:
                reason = "multiple_post_anchors"
            elif len(valid_posts) == 0:
                reason = "incomplete_post_anchor"
            else:
                reason = "unresolved_other"

        unresolved.append({
            "event_id": event["event_id"],
            "flow_id": flow_id,
            "security_event_type": event["security_event_type"],
            "reason": reason,
        })

    unresolved.sort(key=lambda e: e["event_id"])

    # Every selected source record must appear exactly once.
    source_ids = sorted(e["event_id"] for e in selected)

    output_ids = sorted(
        [
            item["event_id"]
            for flow in resolved
            for item in flow["evidence"]
        ]
        + [e["event_id"] for e in unresolved]
    )

    assert source_ids == output_ids, (
        "HTTP evidence lost or duplicated during audit"
    )

    return {
        "resolved_flows": resolved,
        "unresolved_evidence": unresolved,
    }


"""Audit shared incident evidence without changing correlation decisions."""

from collections import defaultdict


def audit_incident_evidence(incidents, source_lookup):
    references = defaultdict(list)

    for incident in incidents:
        incident_id = incident["incident_id"]

        for entry in incident["timeline"]:
            for event_id in entry["event_ids"]:
                if event_id not in source_lookup:
                    raise ValueError("Unknown source evidence: " + event_id)

                references[event_id].append({
                    "incident_id": incident_id,
                    "scenario": incident["scenario"],
                    "role": entry["role"],
                    "security_event_type": entry["security_event_type"],
                })

    shared = []
    incident_shared = defaultdict(list)

    for event_id, uses in sorted(references.items()):
        incident_ids = sorted(set(
            use["incident_id"] for use in uses
        ))

        if len(incident_ids) != len(uses):
            raise ValueError(
                "Repeated source ID inside one incident: " + event_id
            )

        if len(incident_ids) <= 1:
            continue

        original = source_lookup[event_id]
        event_type = original.get("security_event_type")

        if not (
            original.get("source") == "wazuh"
            and event_type in {"file_created", "file_modified"}
            and all(
                use["scenario"] == "http_data_exfiltration"
                and use["role"] == "supporting"
                and use["security_event_type"] == event_type
                for use in uses
            )
        ):
            raise ValueError(
                "Unexpected shared evidence: " + event_id
            )

        record = {
            "event_id": event_id,
            "security_event_type": event_type,
            "shared": True,
            "reference_count": len(incident_ids),
            "incident_ids": incident_ids,
        }
        shared.append(record)

        for incident_id in incident_ids:
            incident_shared[incident_id].append(event_id)

    return {
        "total_source_references": sum(
            len(v) for v in references.values()
        ),
        "distinct_source_event_ids": len(references),
        "shared_fim_evidence": shared,
        "shared_fim_source_count": len(shared),
        "incident_shared_evidence_ids": {
            incident_id: sorted(event_ids)
            for incident_id, event_ids
            in sorted(incident_shared.items())
        },
        "interpretation": (
            "Shared FIM is supporting temporal context only. "
            "Reuse across incidents must not be counted as "
            "independent file events or proof of exfiltration."
        ),
    }

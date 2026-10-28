"""Build evidence-separated knowledge context for SOC incidents.

Gantt 3.6: no LLM, no Ground Truth, no automatic MITRE conclusions.
"""

import json
from pathlib import Path

try:
    from knowledge_base.retriever import load_knowledge, retrieve
except ModuleNotFoundError:
    from retriever import load_knowledge, retrieve


def build_knowledge_context(incident, top_k=5):
    """Return source-backed investigation guidance for one incident.

    This result is reference knowledge, NOT evidence or an incident verdict.
    """

    if not isinstance(incident, dict):
        raise ValueError("Incident must be a dictionary")

    incident_id = incident.get("incident_id")
    scenario = incident.get("scenario")
    timeline = incident.get("timeline")

    if not isinstance(incident_id, str) or not incident_id:
        raise ValueError("Missing incident_id")

    if scenario not in {"ssh_brute_force", "http_data_exfiltration"}:
        raise ValueError("Unsupported incident scenario")

    if not isinstance(timeline, list) or not timeline:
        raise ValueError("Missing or empty incident timeline")

    if not all(isinstance(entry, dict) for entry in timeline):
        raise ValueError("Invalid timeline entries")

    event_types = sorted({
        entry["security_event_type"]
        for entry in timeline
        if isinstance(entry.get("security_event_type"), str)
        and entry["security_event_type"]
    })

    if not event_types:
        raise ValueError("No usable security_event_type")

    candidates = retrieve(
        incident_type=scenario,
        event_types=event_types,
        top_k=top_k,
    )

    knowledge = {
        doc["document_id"]: doc
        for doc in load_knowledge()
    }

    context_documents = []

    for result in candidates:
        document_id = result["document_id"]
        document = knowledge[document_id]

        if document["scenario"] not in (scenario, "both"):
            raise ValueError("Cross-scenario knowledge detected")

        if document["source_sha256"] != result["source_sha256"]:
            raise ValueError("Knowledge source provenance mismatch")

        context_documents.append({
            "document_id": document_id,
            "document_type": document["document_type"],
            "title": document["title"],
            "scenario": document["scenario"],
            "technique": list(document["technique"]),
            "behavior": document["behavior"],
            "evidence_to_check": list(document["evidence_to_check"]),
            "investigation_steps": list(document["investigation_steps"]),
            "recommendations": list(document["recommendations"]),
            "insufficient_evidence_conditions": list(
                document["insufficient_evidence_conditions"]
            ),
            "additional_evidence_to_request": list(
                document.get("additional_evidence_to_request", [])
            ),
            "source_reference": document["source_reference"],
            "source_sha256": document["source_sha256"],
            "mapping_policy": document["mapping_policy"],
            "retrieval": {
                "relevance_score": result["relevance_score"],
                "reasons": list(result["retrieval_reasons"]),
                "matched_event_types": list(result["matched_event_types"]),
                "matched_keywords": list(result["matched_keywords"]),
            },
        })

    return {
        "schema_version": "1.0",
        "gantt_task": "3.6",
        "incident_id": incident_id,
        "incident_scenario": scenario,
        "observed_event_types": event_types,
        "document_count": len(context_documents),
        "knowledge_documents": context_documents,
        "policy": {
            "knowledge_is_incident_evidence": False,
            "ground_truth_used": False,
            "mitre_mapping_confirmed": False,
            "retrieval_score_is_confidence": False,
            "factual_findings_require_event_ids": True,
            "human_review_required": True,
        },
    }


def build_from_incident_id(incident_id, incidents_path=None, top_k=5):
    """Locate an incident in the frozen baseline and build its context."""

    if incidents_path is None:
        incidents_path = (
            Path(__file__).resolve().parent.parent
            / "data_processing"
            / "normalized"
            / "incident_correlation_baseline"
            / "incidents.json"
        )

    incidents = json.loads(
        Path(incidents_path).read_text(encoding="utf-8")
    )

    matches = [
        incident for incident in incidents
        if incident.get("incident_id") == incident_id
    ]

    if len(matches) != 1:
        raise ValueError("Incident ID not uniquely found")

    return build_knowledge_context(matches[0], top_k=top_k)

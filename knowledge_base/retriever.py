"""Deterministic, metadata-based security knowledge retrieval.

Gantt 3.5: retrieval only. No LLM, Ground Truth, or incident conclusions.
"""

import hashlib
import json
import re
from pathlib import Path


COLLECTION_PATH = (
    Path(__file__).resolve().parent / "normalized" / "documents.json"
)

ALLOWED_SCENARIOS = {
    "ssh_brute_force",
    "http_data_exfiltration",
}


def _tokens(value):
    """Normalize query text into a set of searchable tokens."""
    return set(re.findall(r"[a-z0-9_]+", str(value).lower()))


def load_knowledge(collection_path=None):
    """Load normalized documents and verify their source provenance."""
    path = Path(collection_path) if collection_path else COLLECTION_PATH
    collection = json.loads(path.read_text(encoding="utf-8"))

    if collection.get("ground_truth_used_for_retrieval") is not False:
        raise ValueError("Ground Truth exclusion policy missing")

    if collection.get("knowledge_is_incident_evidence") is not False:
        raise ValueError("Knowledge/evidence separation policy missing")

    documents = collection.get("documents")
    if not isinstance(documents, list) or len(documents) != 6:
        raise ValueError("Unexpected knowledge document count")

    ids = [doc["document_id"] for doc in documents]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate knowledge document IDs")

    kb_root = path.resolve().parent.parent

    for doc in documents:
        if doc.get("mapping_policy") != (
            "candidate_requires_evidence_review"
        ):
            raise ValueError("Unsafe MITRE mapping policy")

        relative_path = Path(doc["source_document"])

        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("Unsafe source document path")

        source_path = (kb_root / relative_path).resolve()
        if not source_path.is_relative_to(kb_root):
            raise ValueError("Source path escapes knowledge base")

        actual_hash = hashlib.sha256(
            source_path.read_bytes()
        ).hexdigest()

        if actual_hash != doc["source_sha256"]:
            raise ValueError(
                "Knowledge source checksum mismatch: "
                + doc["document_id"]
            )

    return documents


def retrieve(
    incident_type,
    event_types=None,
    keywords=None,
    top_k=5,
    collection_path=None,
):
    """Find scenario-relevant knowledge without using Ground Truth.

    Args:
        incident_type: ssh_brute_force or http_data_exfiltration.
        event_types: observed security_event_type values.
        keywords: optional search text or list of search terms.
        top_k: maximum number of returned documents.

    Returns:
        Ranked list of candidate knowledge documents. The scores
        indicate retrieval relevance, not probability of attack.
    """
    if incident_type not in ALLOWED_SCENARIOS:
        raise ValueError("Unsupported incident type")

    if not isinstance(top_k, int) or isinstance(top_k, bool):
        raise ValueError("top_k must be an integer")
    if not 1 <= top_k <= 6:
        raise ValueError("top_k must be between 1 and 6")

    if isinstance(event_types, str):
        event_types = [event_types]
    if isinstance(keywords, str):
        keywords = [keywords]

    observed = set(event_types or [])
    query_tokens = set()

    for item in keywords or []:
        query_tokens.update(_tokens(item))

    results = []

    for doc in load_knowledge(collection_path):
        scenario = doc["scenario"]

        # Hard scenario filter prevents SSH/HTTP cross-contamination.
        if scenario not in (incident_type, "both"):
            continue

        matched_events = sorted(
            observed.intersection(doc["evidence_to_check"])
        )

        searchable = " ".join([
            doc["title"],
            doc["behavior"],
            " ".join(doc["technique"]),
            " ".join(doc["evidence_to_check"]),
        ])
        matched_keywords = sorted(
            query_tokens.intersection(_tokens(searchable))
        )

        # The score is a deterministic ranking heuristic.
        score = (
            (100 if scenario == incident_type else 20)
            + 10 * len(matched_events)
            + 2 * len(matched_keywords)
        )

        reasons = [
            "scenario_match" if scenario == incident_type
            else "general_triage"
        ]

        if matched_events:
            reasons.append("evidence_type_match")
        if matched_keywords:
            reasons.append("keyword_match")

        results.append({
            "document_id": doc["document_id"],
            "document_type": doc["document_type"],
            "title": doc["title"],
            "scenario": scenario,
            "technique": list(doc["technique"]),
            "relevance_score": score,
            "matched_event_types": matched_events,
            "matched_keywords": matched_keywords,
            "retrieval_reasons": reasons,
            "source_reference": doc["source_reference"],
            "source_sha256": doc["source_sha256"],
            "mapping_policy": doc["mapping_policy"],
        })

    return sorted(
        results,
        key=lambda item: (
            -item["relevance_score"],
            item["document_id"],
        ),
    )[:top_k]

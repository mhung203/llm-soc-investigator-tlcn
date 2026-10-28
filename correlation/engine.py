"""Unified SOC correlation engine.

Ground truth and experiment run identifiers are not correlation inputs.
"""

from correlation.ssh_rules import correlate_ssh
from correlation.http_rules import (
    correlate_http_with_audit,
    correlate_fim_http,
)

SSH_SCENARIO = "ssh_brute_force"
HTTP_SCENARIO = "http_data_exfiltration"


def correlate_events(events, scenario):
    """Correlate classified events for one explicit security scenario."""
    if scenario == SSH_SCENARIO:
        result = correlate_ssh(events)

        return {
            "scenario": scenario,
            "correlation_window_seconds": 30,
            "activity_groups": result["activity_groups"],
            "ungrouped_ssh_failures": result["ungrouped_ssh_failures"],
            "password_evidence": result["password_evidence"],
            "additional_evidence": result["additional_evidence"],
            "disconnect_evidence": result["disconnect_evidence"],
        }

    if scenario == HTTP_SCENARIO:
        audit = correlate_http_with_audit(events)
        enriched = correlate_fim_http(events, window_seconds=60)

        # FIM enrichment must preserve all resolved HTTP flows.
        def flow_key(flow):
            return (str(flow["flow_id"]), flow["post_event_id"])

        audit_keys = [flow_key(f) for f in audit["resolved_flows"]]
        enriched_keys = [flow_key(f) for f in enriched]

        assert len(audit_keys) == len(set(audit_keys)), (
            "Duplicate HTTP flow keys in audit"
        )
        assert len(enriched_keys) == len(set(enriched_keys)), (
            "Duplicate HTTP flow keys after FIM enrichment"
        )
        assert set(audit_keys) == set(enriched_keys), (
            "HTTP flows changed during FIM enrichment"
        )

        return {
            "scenario": scenario,
            "correlation_window_seconds": 60,
            "http_flows": enriched,
            "unresolved_http_evidence": audit["unresolved_evidence"],
        }

    raise ValueError(f"Unsupported correlation scenario: {scenario}")

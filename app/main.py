from __future__ import annotations

import json
import uuid

from app.correlation.engine import CorrelationEngine
from app.evidence.aggregator import aggregate_evidence
from app.enrichment.attack_mapper import map_incident_to_attack
from app.risk.scorer import RiskScorer
from app.schemas.alert import Alert
from app.schemas.incident import Incident


correlation_engine = CorrelationEngine()
risk_scorer = RiskScorer()


def parse_alert(raw_alert: str | bytes) -> Alert:
    """Convert a raw Redis alert into a validated Alert object."""
    if isinstance(raw_alert, bytes):
        raw_alert = raw_alert.decode("utf-8")

    data = json.loads(raw_alert)
    return Alert.model_validate(data)


def deduplicate_alerts(
    alerts: list[Alert],
    time_tolerance: float = 1.0,
) -> list[Alert]:
    """
    Remove obvious duplicate detector alerts.

    Alerts are considered duplicates when they have the same:
    - threat class
    - source IP
    - destination IP
    - flow ID

    and occur within the specified timestamp tolerance.

    This does not deduplicate alerts based only on source/destination,
    because repeated detections can be meaningful evidence.
    """
    unique_alerts: list[Alert] = []

    for alert in sorted(alerts, key=lambda item: item.timestamp):
        is_duplicate = False

        for existing in reversed(unique_alerts):
            if alert.timestamp - existing.timestamp > time_tolerance:
                break

            if (
                alert.threat_class == existing.threat_class
                and alert.src_ip == existing.src_ip
                and alert.dst_ip == existing.dst_ip
                and alert.flow_id is not None
                and alert.flow_id == existing.flow_id
            ):
                is_duplicate = True
                break

        if not is_duplicate:
            unique_alerts.append(alert)

    return unique_alerts


def process_alerts(
    raw_alerts: list[str | bytes],
    generate_llm_narrative: bool = False,
) -> list[Incident]:
    """
    Process alerts through the correlation/risk pipeline.

    LLM narrative generation is OPTIONAL.

    By default:
        Detection -> Correlation -> Risk -> Evidence -> ATT&CK

    If generate_llm_narrative=True:
        the LLM narrative is generated after the incident
        has already been constructed.
    """
    alerts = [parse_alert(raw_alert) for raw_alert in raw_alerts]

    # Remove obvious duplicate detector alerts.
    alerts = deduplicate_alerts(alerts)

    # Correlate alerts into incidents.
    incidents = correlation_engine.create_incidents(alerts)

    results: list[Incident] = []

    for incident_alerts in incidents:
        # Calculate incident-level risk.
        risk = risk_scorer.calculate_risk(incident_alerts)

        # Collect distinct detector/threat types.
        threat_types = list(
            {
                alert.threat_class.value
                for alert in incident_alerts
            }
        )

        # Aggregate detector evidence.
        evidence = aggregate_evidence(incident_alerts)

        # Map supported alerts to MITRE ATT&CK techniques.
        attack_techniques = map_incident_to_attack(incident_alerts)

        # Create the incident immediately.
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            alerts=incident_alerts,
            threat_types=threat_types,
            risk=risk,
            evidence=evidence,
            attack_techniques=attack_techniques,
            narrative="",
        )

        # ---------------------------------------------------------
        # OPTIONAL LLM ENRICHMENT
        # ---------------------------------------------------------
        #
        # The incident is already complete without the LLM.
        #
        # The LLM is only called when explicitly requested.
        #
        if generate_llm_narrative:
            from app.narrative.generator import generate_narrative

            incident.narrative = generate_narrative(incident)

        results.append(incident)

    return results
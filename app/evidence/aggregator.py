from __future__ import annotations

from typing import Any

from app.schemas.alert import Alert


def aggregate_evidence(
    alerts: list[Alert],
) -> dict[str, Any]:
    """
    Aggregate detector evidence from all alerts in an incident.
    """

    evidence: dict[str, Any] = {}

    for index, alert in enumerate(alerts, start=1):
        threat_name = alert.threat_class.value

        evidence[f"{threat_name}_{index}"] = {
            "confidence": alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "flow_id": alert.flow_id,
            "detector_evidence": alert.evidence,
        }

    return evidence
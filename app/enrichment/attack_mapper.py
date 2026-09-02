from __future__ import annotations

from app.schemas.alert import Alert


ATTACK_MAPPING: dict[str, list[dict[str, str]]] = {
    "Recon/Scanning": [
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
        }
    ],
    "C2 Beaconing": [
        {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
        }
    ],
    "Potential Data Exfiltration / Abnormal Outbound Transfer": [
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
        }
    ],
    "SYN-flood-like traffic anomaly": [
        {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
        }
    ],
    "DNS Tunnelling": [
        {
            "technique_id": "T1071.004",
            "technique_name": "DNS",
        }
    ],
    "DGA": [
        {
            "technique_id": "T1568.002",
            "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        }
    ],
    "Encrypted-Session Behavioral Anomaly Detection": [],
}


def map_alert_to_attack(alert: Alert) -> list[dict[str, str]]:
    """
    Map one detector alert to ATT&CK techniques.

    Returns an empty list when no deterministic mapping is
    currently defined.
    """

    return ATTACK_MAPPING.get(
        alert.threat_class.value,
        [],
    )


def map_incident_to_attack(
    alerts: list[Alert],
) -> list[dict[str, str]]:
    """
    Collect unique ATT&CK techniques represented by an incident.
    """

    techniques: dict[str, dict[str, str]] = {}

    for alert in alerts:
        for technique in map_alert_to_attack(alert):
            techniques[technique["technique_id"]] = technique

    return list(techniques.values())
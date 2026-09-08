from app.enrichment.attack_mapper import map_alert_to_attack
from app.schemas.alert import Alert
from src.detection.schemas import ThreatClass


def make_alert(
    threat_class: ThreatClass,
    evidence: dict | None = None,
) -> Alert:
    return Alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=threat_class,
        confidence=0.8,
        evidence=evidence or {},
    )


def test_recon_maps_to_network_service_scanning():
    alert = make_alert(
        ThreatClass.RECON,
        evidence={"ports": 50},
    )

    techniques = map_alert_to_attack(alert)

    assert len(techniques) == 1
    assert techniques[0]["technique_id"] == "T1046"
    assert techniques[0]["technique_name"] == "Network Service Scanning"


def test_c2_maps_to_application_layer_protocol():
    alert = make_alert(
        ThreatClass.C2_BEACONING,
        evidence={
            "mean_interval": 3.8,
            "cov": 0.2,
        },
    )

    techniques = map_alert_to_attack(alert)

    assert len(techniques) == 1
    assert techniques[0]["technique_id"] == "T1071"


def test_encrypted_anomaly_has_no_unsupported_mapping():
    alert = make_alert(ThreatClass.ENCRYPTED_ANOMALY)

    techniques = map_alert_to_attack(alert)

    assert techniques == []


def test_c2_without_supporting_evidence_has_no_attack_mapping():
    alert = make_alert(
        ThreatClass.C2_BEACONING,
        evidence={},
    )

    techniques = map_alert_to_attack(alert)

    assert techniques == []
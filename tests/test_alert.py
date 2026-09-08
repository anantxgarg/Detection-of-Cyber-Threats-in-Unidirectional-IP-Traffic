import pytest
from app.schemas.alert import Alert
from src.detection.schemas import ThreatClass


def test_alert_validation_and_fields():
    alert = Alert(
        timestamp=1312968035.28,
        flow_id="test-flow-1",
        src_ip="147.32.84.165",
        dst_ip="66.94.238.147",
        protocol="tcp",
        threat_class=ThreatClass.C2_BEACONING,
        confidence=0.85,
        evidence={"mean_interval_sec": 3.8, "cov": 0.12},
    )

    assert alert.src_ip == "147.32.84.165"
    assert alert.dst_ip == "66.94.238.147"
    assert alert.protocol == "tcp"
    assert alert.threat_class == ThreatClass.C2_BEACONING
    assert alert.threat_class.value == "C2 Beaconing"
    assert alert.confidence == 0.85
    assert alert.evidence["cov"] == 0.12


def test_alert_serialization_roundtrip():
    alert = Alert(
        timestamp=1312968035.28,
        src_ip="147.32.84.165",
        threat_class=ThreatClass.DDOS,
        confidence=0.9,
        evidence={"s0_count": 44},
    )

    json_data = alert.model_dump_json()
    loaded = Alert.model_validate_json(json_data)

    assert loaded.timestamp == alert.timestamp
    assert loaded.src_ip == alert.src_ip
    assert loaded.dst_ip is None
    assert loaded.threat_class == ThreatClass.DDOS
    assert loaded.evidence["s0_count"] == 44


def test_alert_allows_extra_fields():
    data = {
        "timestamp": 1312968035.0,
        "src_ip": "10.0.0.1",
        "threat_class": "Recon/Scanning",
        "confidence": 0.7,
        "evidence": {},
        "custom_metadata": "ctu13-experiment",
    }
    alert = Alert.model_validate(data)
    assert alert.src_ip == "10.0.0.1"
    assert getattr(alert, "custom_metadata", None) == "ctu13-experiment"

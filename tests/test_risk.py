from app.risk.scorer import RiskScorer
from app.schemas.alert import Alert
from src.detection.schemas import ThreatClass


def make_alert(
    timestamp: float,
    src_ip: str,
    threat_class: ThreatClass,
    dst_ip: str | None = None,
    flow_id: str | None = None,
) -> Alert:
    return Alert(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        flow_id=flow_id,
        threat_class=threat_class,
        confidence=0.8,
        evidence={},
    )


def test_risk_increases_with_detector_diversity():
    alert = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.C2_BEACONING,
    )

    scorer = RiskScorer()

    single_risk = scorer.calculate_risk([alert])

    alerts = [
        alert,
        make_alert(
            timestamp=1050,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.20",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=1100,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.30",
            threat_class=ThreatClass.EXFILTRATION,
        ),
    ]

    correlated_risk = scorer.calculate_risk(alerts)

    assert correlated_risk > single_risk


def test_empty_incident_has_zero_risk():
    scorer = RiskScorer()

    assert scorer.calculate_risk([]) == 0.0

def test_all_alert_confidences_contribute_to_risk():
    scorer = RiskScorer()

    alerts_high = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.5",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=1050,
            src_ip="10.0.0.5",
            threat_class=ThreatClass.C2_BEACONING,
        ),
    ]

    # Create the same incident, but lower the confidence
    # of the second detector.
    alerts_low = [
        alerts_high[0],
        alerts_high[1].model_copy(update={"confidence": 0.2}),
    ]

    high_risk = scorer.calculate_risk(alerts_high)
    low_risk = scorer.calculate_risk(alerts_low)

    assert high_risk > low_risk
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

def test_multi_detector_chain_has_higher_risk_than_isolated_alert():
    """
    Red-zone validation:
    A correlated multi-detector incident must have higher risk
    than an isolated alert, even when the individual alert
    confidence is the same.
    """

    scorer = RiskScorer()

    isolated_alert = make_alert(
        timestamp=1000,
        src_ip="10.0.0.50",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.C2_BEACONING,
    )

    chain_alerts = [
        isolated_alert,
        make_alert(
            timestamp=1050,
            src_ip="10.0.0.50",
            dst_ip="203.0.113.20",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=1100,
            src_ip="10.0.0.50",
            dst_ip="198.51.100.30",
            threat_class=ThreatClass.EXFILTRATION,
        ),
    ]

    isolated_risk = scorer.calculate_risk([isolated_alert])
    chain_risk = scorer.calculate_risk(chain_alerts)

    assert chain_risk > isolated_risk

def test_risk_is_bounded_between_zero_and_one():
    scorer = RiskScorer()

    alert = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={"confidence": 1.0}
    )

    risk = scorer.calculate_risk([alert])

    assert 0.0 <= risk <= 1.0

def test_low_confidence_incident_has_lower_risk():
    scorer = RiskScorer()

    high_confidence = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={"confidence": 0.9}
    )

    low_confidence = high_confidence.model_copy(
        update={"confidence": 0.2}
    )

    assert scorer.calculate_risk([low_confidence]) < scorer.calculate_risk(
        [high_confidence]
    )

def test_invalid_risk_weights_are_rejected():
    try:
        RiskScorer(
            confidence_weight=-0.1,
            diversity_weight=1.1,
        )
        assert False
    except ValueError:
        assert True

def test_zero_total_risk_weights_are_rejected():
    try:
        RiskScorer(
            confidence_weight=0.0,
            diversity_weight=0.0,
        )
        assert False
    except ValueError:
        assert True
from app.correlation.features import compute_pair_features
from app.correlation.engine import CorrelationEngine
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


def test_same_source_and_temporal_proximity():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    )

    alert_b = make_alert(
        timestamp=1100,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_source is True
    assert features.same_destination is False
    assert features.time_delta == 100
    assert features.temporal_proximity > 0
    assert features.different_threat_class is True


def test_same_destination_and_flow():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-123",
        threat_class=ThreatClass.EXFILTRATION,
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-123",
        threat_class=ThreatClass.C2_BEACONING,
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_source is True
    assert features.same_destination is True
    assert features.same_flow is True
    assert features.different_threat_class is True


def test_no_relationship_outside_temporal_window():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    )

    alert_b = make_alert(
        timestamp=2000,
        src_ip="10.0.0.6",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_source is False
    assert features.same_destination is False
    assert features.same_flow is False
    assert features.temporal_proximity == 0.0


def test_correlation_engine_groups_related_alerts():
    alerts = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=1050,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.20",
            threat_class=ThreatClass.C2_BEACONING,
        ),
        make_alert(
            timestamp=1100,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.30",
            threat_class=ThreatClass.EXFILTRATION,
        ),
    ]

    engine = CorrelationEngine(
        temporal_window=300,
        correlation_threshold=0.5,
    )

    incidents = engine.create_incidents(alerts)

    assert len(incidents) == 1
    assert len(incidents[0]) == 3


def test_correlation_engine_separates_unrelated_alerts():
    alerts = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=2000,
            src_ip="10.0.0.6",
            dst_ip="192.168.1.20",
            threat_class=ThreatClass.C2_BEACONING,
        ),
    ]

    engine = CorrelationEngine(
        temporal_window=300,
        correlation_threshold=0.5,
    )

    incidents = engine.create_incidents(alerts)

    assert len(incidents) == 2
    assert all(len(incident) == 1 for incident in incidents)


def test_correlation_engine_rejects_same_destination_outside_temporal_window():
    """
    Regression test for the temporal-boundary bug.

    Two alerts share the same source and destination, but occur
    more than 300 seconds apart. They must NOT be correlated.
    """

    alerts = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            threat_class=ThreatClass.C2_BEACONING,
        ),
        make_alert(
            timestamp=2000,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            threat_class=ThreatClass.DGA,
        ),
    ]

    engine = CorrelationEngine(
        temporal_window=300,
        correlation_threshold=0.5,
    )

    incidents = engine.create_incidents(alerts)

    assert len(incidents) == 2
    assert all(len(incident) == 1 for incident in incidents)
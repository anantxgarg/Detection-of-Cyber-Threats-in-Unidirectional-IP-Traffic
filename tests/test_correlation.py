from app.correlation.features import (
    compute_pair_features,
)
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

def test_true_recon_c2_exfil_chain_collapses_into_one_incident():
    """
    Red-zone validation:
    A synthetic Recon -> C2 -> Exfil chain from the same source
    and within the temporal window must collapse into one incident.

    The correlation engine must derive this from observable
    relationships rather than a hard-coded attack sequence.
    """

    alerts = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.50",
            dst_ip="192.168.1.10",
            threat_class=ThreatClass.RECON,
        ),
        make_alert(
            timestamp=1050,
            src_ip="10.0.0.50",
            dst_ip="203.0.113.20",
            threat_class=ThreatClass.C2_BEACONING,
        ),
        make_alert(
            timestamp=1100,
            src_ip="10.0.0.50",
            dst_ip="198.51.100.30",
            threat_class=ThreatClass.EXFILTRATION,
        ),
    ]

    engine = CorrelationEngine(
        temporal_window=300,
        correlation_threshold=0.5,
    )

    incidents = engine.create_incidents(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert len(incident) == 3

    threat_types = {alert.threat_class for alert in incident}

    assert threat_types == {
        ThreatClass.RECON,
        ThreatClass.C2_BEACONING,
        ThreatClass.EXFILTRATION,
    }

def test_false_correlation_shared_infrastructure_does_not_merge_unrelated_hosts():
    """
    Red-zone validation:
    Unrelated hosts contacting the same shared infrastructure
    (for example, a CDN or DNS resolver) must not be merged
    into one incident.

    The shared-infrastructure penalty should keep the correlation
    weight below the incident threshold.
    """

    shared_destination = "8.8.8.8"

    alerts = [
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.10",
            dst_ip=shared_destination,
            threat_class=ThreatClass.C2_BEACONING,
        ).model_copy(
            update={
                "evidence": {
                    "shared_infrastructure": True,
                }
            }
        ),
        make_alert(
            timestamp=1010,
            src_ip="10.0.0.20",
            dst_ip=shared_destination,
            threat_class=ThreatClass.RECON,
        ).model_copy(
            update={
                "evidence": {
                    "shared_infrastructure": True,
                }
            }
        ),
        make_alert(
            timestamp=1020,
            src_ip="10.0.0.30",
            dst_ip=shared_destination,
            threat_class=ThreatClass.EXFILTRATION,
        ).model_copy(
            update={
                "evidence": {
                    "shared_infrastructure": True,
                }
            }
        ),
    ]

    engine = CorrelationEngine(
        temporal_window=300,
        correlation_threshold=0.5,
    )

    incidents = engine.create_incidents(alerts)

    assert len(incidents) == 3
    assert all(len(incident) == 1 for incident in incidents)

def test_same_destination_can_be_marked_uncommon():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.50",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.9,
            }
        }
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.50",
        threat_class=ThreatClass.EXFILTRATION,
    ).model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.9,
            }
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_destination is True
    assert features.uncommon_destination is True


def test_common_destination_is_not_marked_uncommon():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.1,
            }
        }
    )

    alert_b = make_alert(
        timestamp=1010,
        src_ip="10.0.0.20",
        dst_ip="8.8.8.8",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.1,
            }
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_destination is True
    assert features.uncommon_destination is False

def test_same_baseline_deviation_direction_is_detected():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "above",
            }
        }
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "above",
            }
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_baseline_direction is True


def test_opposite_baseline_deviation_directions_do_not_correlate():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "above",
            }
        }
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "below",
            }
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_baseline_direction is False

def test_shared_infrastructure_is_detected():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "evidence": {
                "shared_infrastructure": True,
            }
        }
    )

    alert_b = make_alert(
        timestamp=1010,
        src_ip="10.0.0.20",
        dst_ip="8.8.8.8",
        threat_class=ThreatClass.RECON,
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_destination is True
    assert features.shared_infrastructure is True


def test_shared_infrastructure_reduces_edge_weight():
    normal_features = compute_pair_features(
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            threat_class=ThreatClass.C2_BEACONING,
        ),
        make_alert(
            timestamp=1010,
            src_ip="10.0.0.20",
            dst_ip="8.8.8.8",
            threat_class=ThreatClass.RECON,
        ),
    )

    shared_features = compute_pair_features(
        make_alert(
            timestamp=1000,
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            threat_class=ThreatClass.C2_BEACONING,
        ).model_copy(
            update={
                "evidence": {
                    "shared_infrastructure": True,
                }
            }
        ),
        make_alert(
            timestamp=1010,
            src_ip="10.0.0.20",
            dst_ip="8.8.8.8",
            threat_class=ThreatClass.RECON,
        ),
    )

    from app.correlation.weighting import calculate_edge_weight

    normal_weight = calculate_edge_weight(normal_features)
    shared_weight = calculate_edge_weight(shared_features)

    assert shared_weight < normal_weight

def test_same_protocol_is_detected():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={
            "protocol": "tcp",
        }
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "protocol": "tcp",
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_protocol is True


def test_different_protocols_are_not_marked_same():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    ).model_copy(
        update={
            "protocol": "tcp",
        }
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    ).model_copy(
        update={
            "protocol": "udp",
        }
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_protocol is False


def test_missing_protocol_does_not_break_correlation():
    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    )

    features = compute_pair_features(alert_a, alert_b)

    assert features.same_protocol is False

def test_same_protocol_increases_edge_weight():
    from app.correlation.weighting import calculate_edge_weight

    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    )

    tcp_a = alert_a.model_copy(update={"protocol": "tcp"})
    tcp_b = alert_b.model_copy(update={"protocol": "tcp"})

    without_protocol = compute_pair_features(
        alert_a,
        alert_b,
    )

    with_protocol = compute_pair_features(
        tcp_a,
        tcp_b,
    )

    normal_weight = calculate_edge_weight(without_protocol)
    protocol_weight = calculate_edge_weight(with_protocol)

    assert protocol_weight > normal_weight

def test_uncommon_destination_increases_edge_weight():
    from app.correlation.weighting import calculate_edge_weight

    common_alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.50",
        threat_class=ThreatClass.C2_BEACONING,
    )

    common_alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.6",
        dst_ip="203.0.113.50",
        threat_class=ThreatClass.EXFILTRATION,
    )

    uncommon_alert_a = common_alert_a.model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.9,
            }
        }
    )

    uncommon_alert_b = common_alert_b.model_copy(
        update={
            "evidence": {
                "destination_rarity": 0.9,
            }
        }
    )

    common_features = compute_pair_features(
        common_alert_a,
        common_alert_b,
    )

    uncommon_features = compute_pair_features(
        uncommon_alert_a,
        uncommon_alert_b,
    )

    common_weight = calculate_edge_weight(common_features)
    uncommon_weight = calculate_edge_weight(uncommon_features)

    assert uncommon_features.uncommon_destination is True
    assert common_features.uncommon_destination is False
    assert uncommon_weight > common_weight

def test_same_baseline_direction_increases_edge_weight():
    from app.correlation.weighting import calculate_edge_weight

    alert_a = make_alert(
        timestamp=1000,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
    )

    alert_b = make_alert(
        timestamp=1050,
        src_ip="10.0.0.6",
        dst_ip="192.168.1.20",
        threat_class=ThreatClass.C2_BEACONING,
    )

    same_direction_a = alert_a.model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "above",
            }
        }
    )

    same_direction_b = alert_b.model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "above",
            }
        }
    )

    opposite_direction_b = alert_b.model_copy(
        update={
            "evidence": {
                "baseline_deviation_direction": "below",
            }
        }
    )

    normal_features = compute_pair_features(
        alert_a,
        alert_b,
    )

    same_direction_features = compute_pair_features(
        same_direction_a,
        same_direction_b,
    )

    opposite_direction_features = compute_pair_features(
        same_direction_a,
        opposite_direction_b,
    )

    normal_weight = calculate_edge_weight(normal_features)
    same_direction_weight = calculate_edge_weight(same_direction_features)
    opposite_direction_weight = calculate_edge_weight(opposite_direction_features)

    assert same_direction_features.same_baseline_direction is True
    assert opposite_direction_features.same_baseline_direction is False
    assert same_direction_weight > normal_weight
    assert same_direction_weight > opposite_direction_weight
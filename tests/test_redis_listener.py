from __future__ import annotations

from app.main import process_alerts
from app.redis_listener import AlertStreamListener
from app.schemas.alert import Alert
from src.detection.schemas import ThreatClass


def make_alert(
    timestamp: float = 1000.0,
    threat_class: ThreatClass = ThreatClass.C2_BEACONING,
    src_ip: str = "10.0.0.5",
    dst_ip: str | None = "192.168.1.10",
    flow_id: str | None = "flow-1",
    confidence: float = 0.7,
) -> Alert:
    return Alert(
        timestamp=timestamp,
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        threat_class=threat_class,
        confidence=confidence,
        evidence={
            "test": True,
        },
    )


def test_listener_default_starts_from_latest():
    listener = AlertStreamListener()

    assert listener.last_id == "$"


def test_listener_can_start_from_beginning():
    listener = AlertStreamListener(
        start_from_beginning=True,
    )

    assert listener.last_id == "0-0"


def test_alert_identity_is_stable():
    listener = AlertStreamListener()

    alert = make_alert()

    identity_1 = listener._alert_identity(alert)
    identity_2 = listener._alert_identity(alert)

    assert identity_1 == identity_2


def test_different_alerts_have_different_identity():
    listener = AlertStreamListener()

    alert_1 = make_alert(
        timestamp=1000.0,
        flow_id="flow-1",
    )

    alert_2 = make_alert(
        timestamp=1001.0,
        flow_id="flow-2",
    )

    assert listener._alert_identity(alert_1) != (
        listener._alert_identity(alert_2)
    )


def test_incident_identity_is_stable():
    listener = AlertStreamListener()

    alert_1 = make_alert(
        timestamp=1000.0,
        flow_id="flow-1",
    )

    alert_2 = make_alert(
        timestamp=1050.0,
        flow_id="flow-2",
        threat_class=ThreatClass.DGA,
    )

    identity_1 = listener._incident_identity(
        [alert_1, alert_2]
    )

    identity_2 = listener._incident_identity(
        [alert_2, alert_1]
    )

    assert identity_1 == identity_2


def test_process_batch_updates_existing_incident():
    listener = AlertStreamListener()

    c2_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
        confidence=0.7,
    )

    dga_alert = make_alert(
        timestamp=1050.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-2",
        confidence=0.8,
    )

    batches = [
        [
            c2_alert.model_dump_json(),
        ],
        [
            c2_alert.model_dump_json(),
            dga_alert.model_dump_json(),
        ],
    ]

    def fake_read_alerts(count=100):
        if batches:
            return batches.pop(0)
        return []

    listener.read_alerts = fake_read_alerts

    first_results = listener.process_batch()

    assert len(first_results) == 1

    first_id = first_results[0].incident_id

    second_results = listener.process_batch()

    assert len(second_results) == 1

    second_incident = second_results[0]

    assert second_incident.incident_id == first_id

    assert len(second_incident.alerts) == 2

    assert set(second_incident.threat_types) == {
        ThreatClass.C2_BEACONING.value,
        ThreatClass.DGA.value,
    }

    assert second_incident.risk > 0.6

    assert len(listener.get_incidents()) == 1


def test_new_correlated_alert_extends_existing_incident():
    listener = AlertStreamListener()

    first_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
        confidence=0.7,
    )

    second_alert = make_alert(
        timestamp=1050.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        flow_id="flow-2",
        confidence=0.8,
    )

    first_results = listener._merge_incidents(
        process_alerts(
            [first_alert.model_dump_json()]
        )
    )

    assert len(first_results) == 1

    first_id = first_results[0].incident_id

    second_results = listener._merge_incidents(
        process_alerts(
            [second_alert.model_dump_json()]
        )
    )

    assert len(second_results) == 1

    updated_incident = second_results[0]

    assert updated_incident.incident_id == first_id

    assert len(updated_incident.alerts) == 2

    assert set(updated_incident.threat_types) == {
        ThreatClass.C2_BEACONING.value,
        ThreatClass.DGA.value,
    }


def test_unrelated_alert_creates_new_incident():
    listener = AlertStreamListener()

    first_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
    )

    unrelated_alert = make_alert(
        timestamp=5000.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.99",
        dst_ip="192.168.50.50",
        flow_id="flow-99",
    )

    first_results = listener._merge_incidents(
        process_alerts(
            [first_alert.model_dump_json()]
        )
    )

    assert len(first_results) == 1

    first_id = first_results[0].incident_id

    second_results = listener._merge_incidents(
        process_alerts(
            [unrelated_alert.model_dump_json()]
        )
    )

    assert len(second_results) == 1

    second_id = second_results[0].incident_id

    assert second_id != first_id

    assert len(listener.get_incidents()) == 2


def test_alert_with_same_identity_is_not_added_twice():
    listener = AlertStreamListener()

    alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
        confidence=0.7,
    )

    # First occurrence creates the incident.
    first_results = listener._merge_incidents(
        process_alerts(
            [alert.model_dump_json()]
        )
    )

    assert len(first_results) == 1

    first_id = first_results[0].incident_id

    # The exact same alert must not generate another
    # incident update.
    second_results = listener._merge_incidents(
        process_alerts(
            [alert.model_dump_json()]
        )
    )

    assert len(second_results) == 0

    # The original incident must still exist.
    incidents = listener.get_incidents()

    assert len(incidents) == 1
    assert incidents[0].incident_id == first_id
    assert len(incidents[0].alerts) == 1


def test_correlated_alert_outside_temporal_window_does_not_extend_incident():
    listener = AlertStreamListener(
        temporal_window=300.0,
    )

    first_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
    )

    late_alert = make_alert(
        timestamp=1401.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-2",
    )

    first_results = listener._merge_incidents(
        process_alerts(
            [first_alert.model_dump_json()]
        )
    )

    assert len(first_results) == 1

    second_results = listener._merge_incidents(
        process_alerts(
            [late_alert.model_dump_json()]
        )
    )

    assert len(second_results) == 1

    incidents = listener.get_incidents()

    assert len(incidents) == 2

    first_incident = incidents[0]
    second_incident = incidents[1]

    assert len(first_incident.alerts) == 1
    assert len(second_incident.alerts) == 1


def test_multiple_alerts_from_same_incident_are_kept():
    listener = AlertStreamListener()

    alerts = [
        make_alert(
            timestamp=1000.0,
            threat_class=ThreatClass.C2_BEACONING,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.10",
            flow_id="flow-1",
            confidence=0.7,
        ),
        make_alert(
            timestamp=1050.0,
            threat_class=ThreatClass.DGA,
            src_ip="10.0.0.5",
            dst_ip="192.168.1.20",
            flow_id="flow-2",
            confidence=0.8,
        ),
        make_alert(
            timestamp=1100.0,
            threat_class=ThreatClass.RECON,
            src_ip="10.0.0.5",
            dst_ip=None,
            flow_id="flow-3",
            confidence=0.85,
        ),
    ]

    raw_alerts = [
        alert.model_dump_json()
        for alert in alerts
    ]

    results = listener._merge_incidents(
        process_alerts(raw_alerts)
    )

    assert len(results) == 1

    incident = results[0]

    assert len(incident.alerts) == 3

    assert set(incident.threat_types) == {
        ThreatClass.C2_BEACONING.value,
        ThreatClass.DGA.value,
        ThreatClass.RECON.value,
    }


def test_incident_risk_is_recalculated_after_new_alert():
    listener = AlertStreamListener()

    first_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
        confidence=0.7,
    )

    second_alert = make_alert(
        timestamp=1050.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.20",
        flow_id="flow-2",
        confidence=0.8,
    )

    first_results = listener._merge_incidents(
        process_alerts(
            [first_alert.model_dump_json()]
        )
    )

    first_risk = first_results[0].risk

    second_results = listener._merge_incidents(
        process_alerts(
            [second_alert.model_dump_json()]
        )
    )

    second_risk = second_results[0].risk

    assert second_risk > first_risk


def test_get_incidents_returns_stored_incidents():
    listener = AlertStreamListener()

    alert = make_alert()

    listener._merge_incidents(
        process_alerts(
            [alert.model_dump_json()]
        )
    )

    incidents = listener.get_incidents()

    assert isinstance(incidents, list)
    assert len(incidents) == 1
    assert isinstance(incidents[0].alerts[0], Alert)
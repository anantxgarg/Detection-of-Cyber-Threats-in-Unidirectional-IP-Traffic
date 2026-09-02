from app.redis_listener import AlertStreamListener
from app.schemas.alert import Alert
from src.detection.schemas import ThreatClass


def make_alert(
    timestamp: float,
    threat_class: ThreatClass,
    src_ip: str = "10.0.0.5",
    dst_ip: str | None = "192.168.1.10",
    flow_id: str | None = None,
    confidence: float = 0.8,
) -> Alert:
    return Alert(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        flow_id=flow_id,
        threat_class=threat_class,
        confidence=confidence,
        evidence={},
    )


def test_alert_identity_is_stable():
    alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.DGA,
        flow_id="flow-1",
    )

    first = AlertStreamListener._alert_identity(alert)
    second = AlertStreamListener._alert_identity(alert)

    assert first == second


def test_incident_identity_is_stable():
    alerts = [
        make_alert(
            timestamp=1000.0,
            threat_class=ThreatClass.C2_BEACONING,
            flow_id="flow-1",
        ),
        make_alert(
            timestamp=1010.0,
            threat_class=ThreatClass.DGA,
            flow_id="flow-2",
        ),
    ]

    first = AlertStreamListener._incident_identity(alerts)

    reversed_alerts = list(reversed(alerts))

    second = AlertStreamListener._incident_identity(
        reversed_alerts
    )

    assert first == second


def test_different_alert_sets_have_different_incident_ids():
    first_alerts = [
        make_alert(
            timestamp=1000.0,
            threat_class=ThreatClass.C2_BEACONING,
            flow_id="flow-1",
        )
    ]

    second_alerts = [
        make_alert(
            timestamp=2000.0,
            threat_class=ThreatClass.DGA,
            flow_id="flow-2",
        )
    ]

    first_id = AlertStreamListener._incident_identity(
        first_alerts
    )

    second_id = AlertStreamListener._incident_identity(
        second_alerts
    )

    assert first_id != second_id

def test_incident_keeps_same_id_when_new_related_alert_arrives():
    listener = AlertStreamListener()

    c2_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-1",
        confidence=0.7,
    )

    # First version of the incident.
    first_incident = listener._incident_identity(
        [c2_alert]
    )

    listener.incidents[first_incident] = type(
        "TestIncident",
        (),
        {
            "alerts": [c2_alert],
            "narrative": "",
        },
    )()

    # A new related alert arrives.
    dga_alert = make_alert(
        timestamp=1050.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-2",
        confidence=0.8,
    )

    new_alert_ids = {
        listener._alert_identity(c2_alert),
        listener._alert_identity(dga_alert),
    }

    existing_alert_ids = {
        listener._alert_identity(c2_alert)
    }

    # The new incident still contains the original C2 alert,
    # so the listener should recognize it as the same incident.
    assert new_alert_ids & existing_alert_ids

from app.schemas.incident import Incident


def test_related_alert_updates_existing_incident_id():
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

    existing_id = "stable-test-incident"

    existing_incident = Incident(
        incident_id=existing_id,
        alerts=[c2_alert],
        threat_types=[ThreatClass.C2_BEACONING.value],
        risk=0.0,
        evidence={},
        attack_techniques=[],
        narrative="",
    )

    listener.incidents[existing_id] = existing_incident

    new_incident = Incident(
        incident_id="temporary-new-id",
        alerts=[c2_alert, dga_alert],
        threat_types=[
            ThreatClass.C2_BEACONING.value,
            ThreatClass.DGA.value,
        ],
        risk=0.0,
        evidence={},
        attack_techniques=[],
        narrative="",
    )

    updated = listener._merge_incidents([new_incident])

    assert len(updated) == 1
    assert updated[0].incident_id == existing_id
    assert len(updated[0].alerts) == 2

def test_process_batch_updates_existing_incident():
    listener = AlertStreamListener()

    c2_alert = make_alert(
        timestamp=1000.0,
        threat_class=ThreatClass.C2_BEACONING,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-c2",
        confidence=0.7,
    )

    dga_alert = make_alert(
        timestamp=1050.0,
        threat_class=ThreatClass.DGA,
        src_ip="10.0.0.5",
        dst_ip="192.168.1.10",
        flow_id="flow-dga",
        confidence=0.8,
    )

    batches = [
        [c2_alert.model_dump_json()],
        [
            c2_alert.model_dump_json(),
            dga_alert.model_dump_json(),
        ],
    ]

    def fake_read_alerts(count: int = 100) -> list[str]:
        if batches:
            return batches.pop(0)
        return []

    listener.read_alerts = fake_read_alerts

    # First batch: only C2.
    first_results = listener.process_batch()

    assert len(first_results) == 1

    first_id = first_results[0].incident_id

    assert len(first_results[0].alerts) == 1
    assert first_results[0].threat_types == [
        ThreatClass.C2_BEACONING.value
    ]

    # Second batch: C2 + related DGA.
    second_results = listener.process_batch()

    assert len(second_results) == 1

    second_incident = second_results[0]

    # The incident must retain its original ID.
    assert second_incident.incident_id == first_id

    # The new DGA alert must be added.
    assert len(second_incident.alerts) == 2

    assert set(second_incident.threat_types) == {
        ThreatClass.C2_BEACONING.value,
        ThreatClass.DGA.value,
    }

    # The incident should now have an elevated multi-type risk.
    assert second_incident.risk > 0.6

    # The listener should still contain only one incident.
    assert len(listener.get_incidents()) == 1
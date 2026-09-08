from app.main import process_alerts


def test_process_alerts_returns_incident_and_risk():
    alerts = [
        """
        {
            "timestamp": 1000,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "Recon/Scanning",
            "confidence": 0.85,
            "evidence": {
                "unique_ports_scanned": 25
            }
        }
        """,
        """
        {
            "timestamp": 1050,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.20",
            "flow_id": "flow-2",
            "threat_class": "C2 Beaconing",
            "confidence": 0.80,
            "evidence": {
                "cov": 0.1
            }
        }
        """,
    ]

    results = process_alerts(alerts)

    assert len(results) == 1

    incident = results[0]

    assert len(incident.alerts) == 2
    assert incident.risk > 0
    assert "Recon/Scanning" in incident.threat_types
    assert "C2 Beaconing" in incident.threat_types


def test_incident_contains_aggregated_evidence():
    alerts = [
        """
        {
            "timestamp": 1000,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "Recon/Scanning",
            "confidence": 0.85,
            "evidence": {
                "unique_ports_scanned": 25
            }
        }
        """,
        """
        {
            "timestamp": 1050,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.20",
            "flow_id": "flow-2",
            "threat_class": "C2 Beaconing",
            "confidence": 0.80,
            "evidence": {
                "cov": 0.1,
                "mean_interval_sec": 60
            }
        }
        """,
    ]

    results = process_alerts(alerts)

    assert len(results) == 1

    evidence = results[0].evidence

    assert len(evidence) == 2

    recon_evidence = evidence["Recon/Scanning_1"]
    c2_evidence = evidence["C2 Beaconing_2"]

    assert recon_evidence["confidence"] == 0.85
    assert recon_evidence["detector_evidence"]["unique_ports_scanned"] == 25

    assert c2_evidence["confidence"] == 0.80
    assert c2_evidence["detector_evidence"]["cov"] == 0.1
    assert c2_evidence["detector_evidence"]["mean_interval_sec"] == 60

def test_incident_contains_attack_techniques():
    alerts = [
        """
        {
            "timestamp": 1000,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "Recon/Scanning",
            "confidence": 0.85,
            "evidence": {
                "unique_ports_scanned": 25
            }
        }
        """,
        """
        {
            "timestamp": 1050,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.20",
            "flow_id": "flow-2",
            "threat_class": "C2 Beaconing",
            "confidence": 0.80,
            "evidence": {
                "cov": 0.1
            }
        }
        """,
    ]

    results = process_alerts(alerts)

    assert len(results) == 1

    techniques = results[0].attack_techniques

    technique_ids = {
        technique["technique_id"]
        for technique in techniques
    }

    assert "T1046" in technique_ids
    assert "T1071" in technique_ids

def test_process_alerts_removes_obvious_duplicate_alerts():
    alerts = [
        """
        {
            "timestamp": 1000.000000,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "DGA",
            "confidence": 0.8,
            "evidence": {
                "query": "example-random-domain.com",
                "entropy": 4.0
            }
        }
        """,
        """
        {
            "timestamp": 1000.000005,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "DGA",
            "confidence": 0.8,
            "evidence": {
                "query": "example-random-domain.com",
                "entropy": 4.0
            }
        }
        """,
    ]

    results = process_alerts(alerts)

    assert len(results) == 1
    assert len(results[0].alerts) == 1

def test_process_alerts_does_not_generate_llm_narrative_by_default():
    alerts = [
        """{
            "timestamp": 1000.0,
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.10",
            "flow_id": "flow-1",
            "threat_class": "DGA",
            "confidence": 0.8,
            "evidence": {
                "query": "example-random-domain.com",
                "entropy": 4.0
            }
        }"""
    ]

    results = process_alerts(alerts)

    assert len(results) == 1
    assert results[0].narrative == ""
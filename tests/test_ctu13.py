from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path

import pytest

from app.enrichment.attack_mapper import map_incident_to_attack
from app.evidence.aggregator import aggregate_evidence
from app.main import deduplicate_alerts, process_alerts
from app.risk.scorer import RiskScorer
from app.schemas.alert import Alert
from src.detection.baseline import BaselineEngine
from src.detection.detectors.c2_beaconing import C2BeaconingDetector
from src.detection.detectors.ddos import DDoSDetector
from src.detection.detectors.dga import DGADetector
from src.detection.detectors.dns_tunnel import DNSTunnelDetector
from src.detection.detectors.encrypted_anomaly import EncryptedAnomalyDetector
from src.detection.detectors.exfiltration import ExfiltrationDetector
from src.detection.detectors.recon import ReconDetector
from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import ConnRecord, DnsRecord, NormalizedEvent, SslRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOGS_DIR = PROJECT_ROOT / "logs"

CTU13_BOTNET_IP = "147.32.84.165"


class MockRedis:
    """Lightweight in-memory Redis mock supporting all 7 detectors and baselines."""

    def __init__(self):
        self.lists = defaultdict(list)
        self.sets = defaultdict(set)
        self.kv = {}

    def pipeline(self):
        return MockPipeline(self)

    def get(self, key: str):
        return self.kv.get(key)

    def setex(self, key: str, time: int, val: str):
        self.kv[key] = str(val)

    def delete(self, *keys: str):
        for k in keys:
            self.kv.pop(k, None)
            self.lists.pop(k, None)
            self.sets.pop(k, None)

    def lrange(self, key: str, start: int, end: int):
        lst = self.lists[key]
        if end == -1:
            return lst[start:]
        return lst[start : end + 1]

    def sadd(self, key: str, *members: str):
        s = self.sets[key]
        added = len([m for m in members if m not in s])
        s.update(str(m) for m in members)
        return added

    def scard(self, key: str):
        return len(self.sets[key])

    def pfcount(self, key: str):
        return len(self.sets[key])


class MockPipeline:
    def __init__(self, r: MockRedis):
        self.r = r
        self.ops = []

    def get(self, key: str):
        self.ops.append(lambda: self.r.kv.get(key))
        return self

    def incr(self, key: str):
        def op():
            val = int(self.r.kv.get(key, 0)) + 1
            self.r.kv[key] = str(val)
            return val

        self.ops.append(op)
        return self

    def incrby(self, key: str, amount: int):
        def op():
            val = int(self.r.kv.get(key, 0)) + int(amount)
            self.r.kv[key] = str(val)
            return val

        self.ops.append(op)
        return self

    def pfadd(self, key: str, *elements):
        def op():
            s = self.r.sets.setdefault(key, set())
            added = len([e for e in elements if e not in s])
            s.update(str(e) for e in elements)
            return 1 if added > 0 else 0

        self.ops.append(op)
        return self

    def sadd(self, key: str, *members: str):
        def op():
            s = self.r.sets.setdefault(key, set())
            added = len([m for m in members if m not in s])
            s.update(str(m) for m in members)
            return added

        self.ops.append(op)
        return self

    def scard(self, key: str):
        def op():
            return len(self.r.sets.get(key, set()))

        self.ops.append(op)
        return self

    def expire(self, key: str, seconds: int):
        self.ops.append(lambda: True)
        return self

    def lpush(self, key: str, *values):
        def op():
            for v in values:
                self.r.lists[key].insert(0, str(v))
            return len(self.r.lists[key])

        self.ops.append(op)
        return self

    def ltrim(self, key: str, start: int, end: int):
        def op():
            lst = self.r.lists[key]
            self.r.lists[key] = lst[
                start : end + 1 if end != -1 else None
            ]
            return True

        self.ops.append(op)
        return self

    def lrange(self, key: str, start: int, end: int):
        self.ops.append(lambda: self.r.lrange(key, start, end))
        return self

    def execute(self):
        return [op() for op in self.ops]


# =====================================================================
# INGESTION TESTS
# =====================================================================


def test_ctu13_conn_log_parsing():
    """Verify that CTU-13 conn.log records parse cleanly into ConnRecord and NormalizedEvent."""
    conn_path = LOGS_DIR / "conn.log"
    assert conn_path.exists(), f"Missing CTU-13 log: {conn_path}"

    records = []

    with open(conn_path, "r", encoding="utf-8") as f:
        for _ in range(50):
            line = f.readline()

            if not line:
                break

            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            rec = ConnRecord.model_validate(data)

            ev = NormalizedEvent(
                log_type="conn",
                data=rec.model_dump(
                    by_alias=True,
                    exclude_none=True,
                ),
                ts=rec.ts,
                src_ip=rec.id_orig_h,
                dst_ip=rec.id_resp_h,
                src_port=rec.id_orig_p,
                dst_port=rec.id_resp_p,
            )

            records.append(ev)

    assert len(records) > 0
    assert any(
        ev.src_ip == CTU13_BOTNET_IP
        for ev in records
    )
    assert all(
        ev.log_type == "conn"
        for ev in records
    )
    assert all(
        isinstance(ev.ts, float)
        for ev in records
    )


def test_ctu13_dns_log_parsing():
    """Verify that CTU-13 dns.log records parse cleanly into DnsRecord and NormalizedEvent."""
    dns_path = LOGS_DIR / "dns.log"
    assert dns_path.exists(), f"Missing CTU-13 log: {dns_path}"

    records = []

    with open(dns_path, "r", encoding="utf-8") as f:
        for _ in range(50):
            line = f.readline()

            if not line:
                break

            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            rec = DnsRecord.model_validate(data)

            ev = NormalizedEvent(
                log_type="dns",
                data=rec.model_dump(
                    by_alias=True,
                    exclude_none=True,
                ),
                ts=rec.ts,
                src_ip=rec.id_orig_h,
                dst_ip=rec.id_resp_h,
                src_port=rec.id_orig_p,
                dst_port=rec.id_resp_p,
            )

            records.append(ev)

    assert len(records) > 0
    assert any(
        ev.src_ip == CTU13_BOTNET_IP
        for ev in records
    )
    assert all(
        ev.log_type == "dns"
        for ev in records
    )


def test_ctu13_ssl_log_parsing():
    """Verify that CTU-13 ssl.log records parse cleanly into SslRecord."""
    ssl_path = LOGS_DIR / "ssl.log"

    if not ssl_path.exists():
        pytest.skip("ssl.log not found in logs directory")

    records = []

    with open(ssl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            rec = SslRecord.model_validate(data)

            ev = NormalizedEvent(
                log_type="ssl",
                data=rec.model_dump(
                    by_alias=True,
                    exclude_none=True,
                ),
                ts=rec.ts,
                src_ip=rec.id_orig_h,
                dst_ip=rec.id_resp_h,
                src_port=rec.id_orig_p,
                dst_port=rec.id_resp_p,
            )

            records.append(ev)

    assert len(records) > 0


# =====================================================================
# DETECTOR TESTS (ALL 7 CORE DETECTORS)
# =====================================================================


def test_ctu13_detector_1_recon():
    """Detector 1/7: Verify ReconDetector flags port scanning / fast fan-out."""
    mock_redis = MockRedis()
    detector = ReconDetector(mock_redis)

    alert = None

    # Simulate scanning 25 unique ports within the window
    for port in range(1, 26):
        ev = NormalizedEvent(
            log_type="conn",
            data={
                "uid": f"recon-scan-{port}",
            },
            ts=1312968000.0 + (port * 0.1),
            src_ip=CTU13_BOTNET_IP,
            dst_ip="10.0.0.1",
            src_port=40000 + port,
            dst_port=port,
        )

        res = detector.analyze(ev)

        if res:
            alert = res
            break

    assert alert is not None, (
        "Reconnaissance detector failed to trigger on port scan"
    )

    assert alert.threat_class == ThreatClass.RECON
    assert alert.src_ip == CTU13_BOTNET_IP
    assert alert.evidence["unique_ports_scanned"] > 20


def test_ctu13_detector_2_c2_beaconing():
    """Detector 2/7: Verify C2BeaconingDetector detects periodic connections from CTU-13."""
    mock_redis = MockRedis()
    detector = C2BeaconingDetector(mock_redis)

    conn_path = LOGS_DIR / "conn.log"
    c2_alert = None

    with open(conn_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            if data.get("id.orig_h") == CTU13_BOTNET_IP:
                rec = ConnRecord.model_validate(data)

                ev = NormalizedEvent(
                    log_type="conn",
                    data=rec.model_dump(
                        by_alias=True,
                        exclude_none=True,
                    ),
                    ts=rec.ts,
                    src_ip=rec.id_orig_h,
                    dst_ip=rec.id_resp_h,
                    src_port=rec.id_orig_p,
                    dst_port=rec.id_resp_p,
                )

                alert = detector.analyze(ev)

                if alert:
                    c2_alert = alert
                    break

    assert c2_alert is not None, (
        "C2 Beaconing was not detected on CTU-13 traffic"
    )

    assert c2_alert.threat_class == ThreatClass.C2_BEACONING
    assert c2_alert.src_ip == CTU13_BOTNET_IP
    assert c2_alert.confidence >= 0.4
    assert "mean_interval_sec" in c2_alert.evidence
    assert "cov" in c2_alert.evidence


def test_ctu13_detector_3_dga():
    """Detector 3/7: Verify DGADetector identifies algorithmic domains with SHAP attribution."""
    detector = DGADetector()

    dga_event = NormalizedEvent(
        log_type="dns",
        data={
            "query": "w.nucleardiscover.com",
        },
        ts=1312974011.0,
        src_ip=CTU13_BOTNET_IP,
        dst_ip="147.32.80.9",
        src_port=1025,
        dst_port=53,
    )

    alert = detector.analyze(dga_event)

    assert alert is not None, (
        "Failed to detect DGA query in CTU-13 data"
    )

    assert alert.threat_class == ThreatClass.DGA
    assert alert.confidence > 0.8
    assert "shap" in alert.evidence
    assert len(alert.evidence["shap"]) > 0

    # Benign domain should NOT trigger DGA
    benign_event = NormalizedEvent(
        log_type="dns",
        data={
            "query": "clients.l.google.com",
        },
        ts=1312974012.0,
        src_ip=CTU13_BOTNET_IP,
        dst_ip="147.32.80.9",
        src_port=1025,
        dst_port=53,
    )

    benign_alert = detector.analyze(benign_event)

    assert benign_alert is None, (
        "False positive triggered on benign google domain"
    )


def test_ctu13_detector_4_dns_tunnel():
    """Detector 4/7: Verify DNSTunnelDetector detects suspicious DNS tunneling queries."""
    mock_redis = MockRedis()
    detector = DNSTunnelDetector(mock_redis)

    ev = NormalizedEvent(
        log_type="dns",
        data={
            "query": "sub.botnet-tunnel.org",
            "qtype_name": "TXT",
        },
        ts=1312970000.0,
        src_ip=CTU13_BOTNET_IP,
        dst_ip="147.32.80.9",
        src_port=1025,
        dst_port=53,
    )

    tunnel_alert = detector.analyze(ev)

    assert tunnel_alert is not None
    assert tunnel_alert.threat_class == ThreatClass.DNS_TUNNELLING
    assert tunnel_alert.src_ip == CTU13_BOTNET_IP
    assert "shap" in tunnel_alert.evidence


def test_ctu13_detector_5_ddos():
    """Detector 5/7: Verify DDoSDetector flags SYN-flood-like traffic anomalies."""
    mock_redis = MockRedis()

    baseline = BaselineEngine()
    baseline.r = mock_redis

    detector = DDoSDetector(
        mock_redis,
        baseline,
    )

    ddos_alert = None

    # Simulate a burst of 50 half-open (S0) connections as recorded in CTU-13 botnet attacks
    for i in range(55):
        ev = NormalizedEvent(
            log_type="conn",
            data={
                "conn_state": "S0",
                "orig_bytes": 0,
            },
            ts=1312968035.0 + (i * 0.1),
            src_ip=CTU13_BOTNET_IP,
            dst_ip="74.125.232.195",
            src_port=1027 + i,
            dst_port=80,
        )

        baseline.update_from_event(ev)

        res = detector.analyze(ev)

        if res:
            ddos_alert = res
            break

    assert ddos_alert is not None, (
        "DDoS / SYN-flood detector failed to trigger"
    )

    assert ddos_alert.threat_class == ThreatClass.DDOS
    assert ddos_alert.src_ip == CTU13_BOTNET_IP
    assert ddos_alert.confidence == 0.9
    assert ddos_alert.evidence["s0_count"] >= 50


def test_ctu13_detector_6_exfiltration():
    """Detector 6/7: Verify ExfiltrationDetector flags abnormal outbound byte transfers."""
    mock_redis = MockRedis()

    baseline = BaselineEngine()
    baseline.r = mock_redis

    detector = ExfiltrationDetector(
        mock_redis,
        baseline,
    )

    ev = NormalizedEvent(
        log_type="conn",
        data={
            "orig_bytes": 180000,
            "uid": "ctu13-exfil-flow",
        },
        ts=1312968035.0,
        src_ip=CTU13_BOTNET_IP,
        dst_ip="198.51.100.44",
        src_port=51234,
        dst_port=443,
    )

    baseline.update_from_event(ev)

    alert = detector.analyze(ev)

    assert alert is not None, (
        "Exfiltration detector failed to trigger on outbound byte surge"
    )

    assert alert.threat_class == ThreatClass.EXFILTRATION
    assert alert.src_ip == CTU13_BOTNET_IP
    assert alert.evidence["bytes_out_bucket"] >= 100000


def test_ctu13_detector_7_encrypted_anomaly():
    """Detector 7/7: Verify EncryptedAnomalyDetector flags JA4 fingerprint concentration."""
    mock_redis = MockRedis()

    baseline = BaselineEngine()
    baseline.r = mock_redis

    detector = EncryptedAnomalyDetector(
        mock_redis,
        baseline,
    )

    # Set baseline connection volume for host
    mock_redis.lists[
        f"history:{CTU13_BOTNET_IP}:conn_count"
    ] = [
        "60",
        "60",
        "60",
    ]

    # JA4 fingerprint from CTU-13 ssl.log
    ctu13_ja4 = (
        "t10i460300_234845559c90_a875e5012fde"
    )

    alert = None

    for i in range(55):
        ev = NormalizedEvent(
            log_type="ssl",
            data={
                "ja4": ctu13_ja4,
                "uid": f"ctu13-ssl-{i}",
            },
            ts=1312968322.0 + i,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="65.55.196.251",
            src_port=1986 + i,
            dst_port=443,
        )

        res = detector.analyze(ev)

        if res:
            alert = res
            break

    assert alert is not None, (
        "Encrypted Anomaly detector failed to trigger on JA4 concentration"
    )

    assert alert.threat_class == ThreatClass.ENCRYPTED_ANOMALY
    assert alert.src_ip == CTU13_BOTNET_IP
    assert alert.evidence["ja4_fingerprint"] == ctu13_ja4


# =====================================================================
# CORRELATION, RISK, MITRE ATT&CK, AND PIPELINE TESTS
# =====================================================================


def test_ctu13_multi_stage_incident_correlation():
    """
    Verify that multiple alerts originating from the CTU-13 infected host
    (C2 Beaconing, DGA, SYN Flood anomaly) are correlated into a single incident.
    """

    alerts = [
        json.dumps({
            "timestamp": 1312968035.0,
            "src_ip": CTU13_BOTNET_IP,
            "flow_id": "ctu13-syn-1",
            "threat_class": "SYN-flood-like traffic anomaly",
            "confidence": 0.90,
            "protocol": "tcp",
            "evidence": {
                "conn_count": 50,
                "s0_count": 44,
            },
        }),

        json.dumps({
            "timestamp": 1312968090.0,
            "src_ip": CTU13_BOTNET_IP,
            "dst_ip": "66.94.238.147",
            "flow_id": "ctu13-c2-1",
            "threat_class": "C2 Beaconing",
            "confidence": 0.85,
            "protocol": "tcp",
            "evidence": {
                "mean_interval_sec": 6.99,
                "cov": 0.12,
            },
        }),

        json.dumps({
            "timestamp": 1312968150.0,
            "src_ip": CTU13_BOTNET_IP,
            "dst_ip": "147.32.80.9",
            "flow_id": "ctu13-dga-1",
            "threat_class": "DGA",
            "confidence": 0.93,
            "protocol": "udp",
            "evidence": {
                "query": "w.nucleardiscover.com",
                "entropy": 3.8,
            },
        }),
    ]

    incidents = process_alerts(alerts)

    assert len(incidents) == 1, (
        "Expected alerts to correlate into a single incident"
    )

    incident = incidents[0]

    assert len(incident.alerts) == 3
    assert "C2 Beaconing" in incident.threat_types
    assert "DGA" in incident.threat_types
    assert (
        "SYN-flood-like traffic anomaly"
        in incident.threat_types
    )


def test_ctu13_risk_scoring_escalation():
    """
    Verify that multi-stage attack behavior in CTU-13 produces an escalated risk score
    substantially higher than a single isolated alert.
    """

    scorer = RiskScorer()

    single_alert = [
        Alert(
            timestamp=1312968035.0,
            src_ip=CTU13_BOTNET_IP,
            threat_class=ThreatClass.C2_BEACONING,
            confidence=0.6,
            evidence={
                "cov": 0.2,
            },
        )
    ]

    single_risk = scorer.calculate_risk(
        single_alert
    )

    multi_stage_alerts = [
        Alert(
            timestamp=1312968035.0,
            src_ip=CTU13_BOTNET_IP,
            threat_class=ThreatClass.C2_BEACONING,
            confidence=0.85,
            evidence={
                "cov": 0.12,
            },
        ),

        Alert(
            timestamp=1312968080.0,
            src_ip=CTU13_BOTNET_IP,
            threat_class=ThreatClass.DGA,
            confidence=0.92,
            evidence={
                "entropy": 3.9,
            },
        ),

        Alert(
            timestamp=1312968120.0,
            src_ip=CTU13_BOTNET_IP,
            threat_class=ThreatClass.DDOS,
            confidence=0.90,
            evidence={
                "conn_count": 50,
            },
        ),
    ]

    multi_risk = scorer.calculate_risk(
        multi_stage_alerts
    )

    assert multi_risk > single_risk

    assert multi_risk >= 0.85, (
        f"Multi-stage CTU-13 risk score {multi_risk} "
        "should be >= 0.85"
    )


def test_ctu13_mitre_attack_mapping():
    """Verify that CTU-13 incident alerts map accurately to MITRE ATT&CK techniques."""

    alerts = [
        Alert(
            timestamp=1312968035.0,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="66.94.238.147",
            threat_class=ThreatClass.C2_BEACONING,
            confidence=0.85,
            protocol="tcp",
            evidence={
                "mean_interval_sec": 6.99,
                "cov": 0.12,
            },
        ),

        Alert(
            timestamp=1312968080.0,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="147.32.80.9",
            threat_class=ThreatClass.DGA,
            confidence=0.92,
            protocol="udp",
            evidence={
                "query": "w.nucleardiscover.com",
                "entropy": 3.8,
            },
        ),

        Alert(
            timestamp=1312968120.0,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="147.32.80.9",
            threat_class=ThreatClass.DDOS,
            confidence=0.90,
            protocol="tcp",
            evidence={
                "s0_count": 44,
            },
        ),
    ]

    techniques = map_incident_to_attack(
        alerts
    )

    technique_ids = {
        t["technique_id"]
        for t in techniques
    }

    assert "T1071" in technique_ids
    assert "T1568.002" in technique_ids
    assert "T1498" in technique_ids


def test_ctu13_evidence_aggregation():
    """Verify that detector evidence is properly aggregated in CTU-13 incidents."""

    alerts = [
        Alert(
            timestamp=1312968090.0,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="66.94.238.147",
            threat_class=ThreatClass.C2_BEACONING,
            confidence=0.85,
            evidence={
                "cov": 0.12,
                "mean_interval_sec": 6.99,
            },
        ),

        Alert(
            timestamp=1312968150.0,
            src_ip=CTU13_BOTNET_IP,
            dst_ip="147.32.80.9",
            threat_class=ThreatClass.DGA,
            confidence=0.93,
            evidence={
                "query": "w.nucleardiscover.com",
                "entropy": 3.8,
            },
        ),
    ]

    evidence = aggregate_evidence(
        alerts
    )

    assert len(evidence) == 2

    c2_ev = evidence[
        "C2 Beaconing_1"
    ]

    assert c2_ev["confidence"] == 0.85
    assert (
        c2_ev["detector_evidence"]["cov"]
        == 0.12
    )


def test_ctu13_all_seven_detectors_integrated():
    """
    End-to-end integration test running all 7 detectors concurrently
    over a stream of CTU-13 events and correlating outputs.
    """

    mock_redis = MockRedis()

    baseline = BaselineEngine()
    baseline.r = mock_redis

    detectors = [
        ReconDetector(mock_redis),
        C2BeaconingDetector(mock_redis),
        DGADetector(),
        DNSTunnelDetector(mock_redis),
        DDoSDetector(mock_redis, baseline),
        ExfiltrationDetector(mock_redis, baseline),
        EncryptedAnomalyDetector(mock_redis, baseline),
    ]

    assert len(detectors) == 7, (
        "All 7 core detectors must be present"
    )

    generated_alerts = []

    # ---------------------------------------------------------------
    # 1. Process CTU-13 conn records until Recon produces an alert.
    # ---------------------------------------------------------------
    recon_alert = None

    with open(
        LOGS_DIR / "conn.log",
        "r",
        encoding="utf-8",
    ) as f:

        for i, line in enumerate(f):
            if i > 1500:
                break

            line = line.strip()

            if not line:
                continue

            data = json.loads(line)

            if data.get("id.orig_h") != CTU13_BOTNET_IP:
                continue

            rec = ConnRecord.model_validate(data)

            ev = NormalizedEvent(
                log_type="conn",
                data=rec.model_dump(
                    by_alias=True,
                    exclude_none=True,
                ),
                ts=rec.ts,
                src_ip=rec.id_orig_h,
                dst_ip=rec.id_resp_h,
                src_port=rec.id_orig_p,
                dst_port=rec.id_resp_p,
            )

            baseline.update_from_event(ev)

            for det in detectors:
                alert = det.analyze(ev)

                if alert:
                    recon_alert = alert
                    break

            if recon_alert is not None:
                break

    assert recon_alert is not None, (
        "No detector alert was generated from CTU-13 conn traffic"
    )

    generated_alerts.append(
        recon_alert.model_dump_json()
    )

    # ---------------------------------------------------------------
    # 2. Generate a DGA alert close to the actual Recon alert.
    #
    # The timestamp is derived from the actual Recon alert instead
    # of using a hard-coded CTU-13 timestamp. This guarantees that
    # the two alerts are inside the 300-second correlation window.
    # ---------------------------------------------------------------
    dga_ev = NormalizedEvent(
        log_type="dns",
        data={
            "query": "w.nucleardiscover.com",
        },
        ts=recon_alert.timestamp + 60.0,
        src_ip=CTU13_BOTNET_IP,
        dst_ip="147.32.80.9",
        src_port=1025,
        dst_port=53,
    )

    dga_alert = None

    for det in detectors:
        res = det.analyze(dga_ev)

        if res and res.threat_class == ThreatClass.DGA:
            dga_alert = res
            break

    assert dga_alert is not None, (
        "DGA detector failed to generate an alert"
    )

    # ---------------------------------------------------------------
    # 3. Add the DGA alert.
    # ---------------------------------------------------------------
    generated_alerts.append(
        dga_alert.model_dump_json()
    )

    assert len(generated_alerts) >= 2

    # ---------------------------------------------------------------
    # 4. Verify both alerts belong to the same source host.
    # ---------------------------------------------------------------
    assert all(
        alert.src_ip == CTU13_BOTNET_IP
        for alert in [
            recon_alert,
            dga_alert,
        ]
    )

    # They should also be temporally close.
    assert abs(
        dga_alert.timestamp - recon_alert.timestamp
    ) <= 300.0

    # ---------------------------------------------------------------
    # 5. Correlate the generated alerts into incidents.
    # ---------------------------------------------------------------
    incidents = process_alerts(
        generated_alerts
    )

    assert len(incidents) >= 1

    # ---------------------------------------------------------------
    # 6. Find the incident containing the Recon alert.
    #
    # Do not assume incidents[0] is the primary incident because
    # incident ordering is not the thing being tested here.
    # ---------------------------------------------------------------
    primary_incident = next(
        (
            incident
            for incident in incidents
            if any(
                alert.threat_class == ThreatClass.RECON
                for alert in incident.alerts
            )
        ),
        None,
    )

    assert primary_incident is not None, (
        "Recon alert was not present in any incident"
    )

    # ---------------------------------------------------------------
    # 7. Verify the multi-stage incident contains both alerts.
    # ---------------------------------------------------------------
    assert len(primary_incident.alerts) >= 2, (
        "Recon and DGA alerts should correlate into one incident"
    )

    threat_types = set(
        primary_incident.threat_types
    )

    assert ThreatClass.RECON.value in threat_types
    assert ThreatClass.DGA.value in threat_types

    # ---------------------------------------------------------------
    # 8. Verify incident risk and enrichment.
    # ---------------------------------------------------------------
    assert primary_incident.risk > 0.6

    assert any(
        alert.src_ip == CTU13_BOTNET_IP
        for alert in primary_incident.alerts
    )

    assert len(
        primary_incident.attack_techniques
    ) > 0
import pytest
import time
import json

from src.detection.schemas import DetectionResult, ThreatClass
from src.detection.baseline import BaselineEngine
from src.detection.engine import DetectionEngine
from src.ingestion.schemas import NormalizedEvent

def test_detection_result_schema():
    result = DetectionResult(
        timestamp=time.time(),
        src_ip="192.168.1.10",
        threat_class=ThreatClass.RECON,
        confidence=0.8,
        evidence={"ports": 50}
    )
    assert result.threat_class == "Recon/Scanning"
    assert result.confidence == 0.8
    assert result.dst_ip is None

def test_baseline_mad():
    baseline = BaselineEngine()
    
    class MockRedis:
        def lrange(self, key, start, end):
            return ['100', '100', '100', '105', '98', '10000']
            
    baseline.r = MockRedis()
    
    median, mad = baseline.get_baseline("1.2.3.4", "bytes_out")
    
    assert median == 100.0
    assert mad == 1.0 # Minimum mad
    
def test_baseline_mad_variance():
    baseline = BaselineEngine()
    
    class MockRedis:
        def lrange(self, key, start, end):
            # values with actual deviation
            return ['10', '20', '30', '40', '50']
            
    baseline.r = MockRedis()
    
    median, mad = baseline.get_baseline("1.2.3.4", "bytes_out")
    
    # median of 10,20,30,40,50 is 30
    assert median == 30.0
    # deviations: 20, 10, 0, 10, 20. sorted: 0, 10, 10, 20, 20
    # median of deviations is 10
    assert mad == 10.0

def test_detection_engine_propagates_protocol_to_alert():
    class FakeRedis:
        def __init__(self):
            self.xadd_calls = []
            self.read_count = 0

        def xread(self, streams, count=100, block=1000):
            if self.read_count == 0:
                self.read_count += 1

                event = {
                    "log_type": "conn",
                    "data": json.dumps({
                        "proto": "TCP",
                    }),
                    "ts": "1000.0",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "192.168.1.10",
                    "src_port": "12345",
                    "dst_port": "80",
                }

                return [
                    (
                        "events:live",
                        [
                            ("1-0", event),
                        ],
                    )
                ]

            raise KeyboardInterrupt

        def xadd(self, stream, data):
            self.xadd_calls.append((stream, data))
            return "2-0"

    class FakeBaseline:
        def update_from_event(self, event):
            pass

    class FakeDetector:
        def analyze(self, event):
            return DetectionResult(
                timestamp=event.ts,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.RECON,
                confidence=0.8,
                evidence={"ports": 50},
            )

    fake_redis = FakeRedis()

    engine = DetectionEngine.__new__(DetectionEngine)
    engine.r = fake_redis
    engine.baseline = FakeBaseline()
    engine.detectors = [FakeDetector()]

    engine.run()

    assert len(fake_redis.xadd_calls) == 1

    stream, data = fake_redis.xadd_calls[0]

    assert stream == "alerts:live"

    alert = json.loads(data["alert"])

    assert alert["protocol"] == "tcp"

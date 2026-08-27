import pytest
import time
from src.detection.schemas import DetectionResult, ThreatClass
from src.detection.baseline import BaselineEngine

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

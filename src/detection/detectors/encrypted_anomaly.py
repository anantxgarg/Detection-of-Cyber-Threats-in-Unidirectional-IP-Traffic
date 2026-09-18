from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
from src.detection.baseline import BaselineEngine
import redis

class EncryptedAnomalyDetector:
    def __init__(self, redis_client: redis.Redis, baseline_engine: BaselineEngine):
        self.r = redis_client
        self.baseline = baseline_engine
        self.window_seconds = 3600
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'ssl':
            return None
            
        src_ip = event.src_ip
        ja4 = event.data.get('ja4')
        
        if not ja4:
            return None
            
        # Count sessions per JA4 fingerprint per host
        ja4_key = f"ja4_count:{src_ip}:{ja4}"
        pipe = self.r.pipeline()
        pipe.incr(ja4_key)
        pipe.expire(ja4_key, self.window_seconds)
        results = pipe.execute()
        
        count = results[0]
        
        conn_median, _ = self.baseline.get_baseline(src_ip, 'conn_count')
        
        # If a single JA4 signature is responsible for an overwhelming majority 
        # of a busy host's traffic, flag it as a behavioral anomaly.
        if conn_median > 50 and count > (conn_median * 0.8):
            alert_key = f"alert_cooldown:ssl_anomaly:{src_ip}:{ja4}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 300, 1)
                
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=src_ip,
                    dst_ip=event.dst_ip,
                    threat_class=ThreatClass.ENCRYPTED_ANOMALY,
                    confidence=0.65,
                    evidence={
                        "ja4_fingerprint": ja4,
                        "fingerprint_connections": count,
                        "host_connection_baseline": conn_median
                    }
                )
        return None

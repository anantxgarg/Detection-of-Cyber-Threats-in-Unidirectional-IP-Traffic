from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
from src.detection.baseline import BaselineEngine
import redis

class ExfiltrationDetector:
    def __init__(self, redis_client: redis.Redis, baseline_engine: BaselineEngine):
        self.r = redis_client
        self.baseline = baseline_engine
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'conn':
            return None
            
        src_ip = event.src_ip
        bucket_ts = self.baseline._get_bucket_ts(event.ts)
        
        b_key = f"bucket:{src_ip}:bytes_out:{bucket_ts}"
        bytes_out = int(self.r.get(b_key) or 0)
        
        if bytes_out < 100000: # Min 100KB to evaluate exfil
            return None
            
        b_median, b_mad = self.baseline.get_baseline(src_ip, 'bytes_out')
        b_dev = (bytes_out - b_median) / b_mad
        
        if b_dev > 5.0:
            alert_key = f"alert_cooldown:exfil:{src_ip}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 300, 1)
                self.r.setex(f"alerting:{src_ip}", 60, 1)
                
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=src_ip,
                    dst_ip=event.dst_ip,
                    threat_class=ThreatClass.EXFILTRATION,
                    confidence=0.8,
                    evidence={
                        "bytes_out_bucket": bytes_out,
                        "bytes_out_median": b_median,
                        "deviation_mad": round(b_dev, 2)
                    }
                )
        return None

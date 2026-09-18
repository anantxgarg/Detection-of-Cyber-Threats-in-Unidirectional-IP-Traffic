from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
from src.detection.baseline import BaselineEngine
import redis

class DDoSDetector:
    def __init__(self, redis_client: redis.Redis, baseline_engine: BaselineEngine):
        self.r = redis_client
        self.baseline = baseline_engine
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'conn':
            return None
            
        src_ip = event.src_ip
        bucket_ts = self.baseline._get_bucket_ts(event.ts)
        c_key = f"bucket:{src_ip}:conn_count:{bucket_ts}"
        s0_key = f"bucket:{src_ip}:half_open:{bucket_ts}"
        
        # Read current bucket
        pipe = self.r.pipeline()
        pipe.get(c_key)
        pipe.get(s0_key)
        results = pipe.execute()
        
        conn_count = int(results[0] or 0)
        s0_count = int(results[1] or 0)
        
        if conn_count < 50:
            return None
            
        conn_median, conn_mad = self.baseline.get_baseline(src_ip, 'conn_count')
        s0_median, s0_mad = self.baseline.get_baseline(src_ip, 'half_open')
        
        conn_dev = (conn_count - conn_median) / conn_mad
        s0_dev = (s0_count - s0_median) / s0_mad
        
        # High connection deviation + high half-open deviation + >50% connections are half-open
        is_syn_flood = conn_dev > 5.0 and s0_dev > 5.0 and (s0_count / conn_count) > 0.5
        
        if is_syn_flood:
            alert_key = f"alert_cooldown:ddos:{src_ip}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 60, 1)
                self.r.setex(f"alerting:{src_ip}", 60, 1) # Guarded updates flag
                
                return DetectionResult(
                    timestamp=event.ts,
                    src_ip=src_ip,
                    threat_class=ThreatClass.DDOS,
                    confidence=0.9,
                    evidence={
                        "conn_count": conn_count,
                        "conn_baseline_median": conn_median,
                        "s0_count": s0_count,
                        "s0_baseline_median": s0_median,
                        "conn_deviation_mad": round(conn_dev, 2)
                    }
                )
        return None

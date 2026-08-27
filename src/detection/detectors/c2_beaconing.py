from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
import redis
import numpy as np
from scipy import signal

class C2BeaconingDetector:
    def __init__(self, redis_client: redis.Redis):
        self.r = redis_client
        self.min_samples = 10
        self.cov_threshold = 0.15 # Low coefficient of variation = regular beacon
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'conn':
            return None
            
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        
        # Track flow timestamps per source-dest pair
        ts_list_key = f"c2_ts:{src_ip}:{dst_ip}"
        
        pipe = self.r.pipeline()
        pipe.lpush(ts_list_key, event.ts)
        pipe.ltrim(ts_list_key, 0, 49) # Keep last 50 connections
        pipe.expire(ts_list_key, 3600) # 1 hour
        pipe.lrange(ts_list_key, 0, -1)
        results = pipe.execute()
        
        raw_ts = results[-1]
        if len(raw_ts) < self.min_samples:
            return None
            
        ts_array = np.array([float(t) for t in raw_ts])[::-1] # reverse to chronological
        intervals = np.diff(ts_array)
        
        if len(intervals) < 2:
            return None
            
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if mean_interval == 0:
            return None
            
        cov = std_interval / mean_interval
        
        # Check periodicity
        is_periodic = False
        if cov < self.cov_threshold:
            is_periodic = True
        elif cov < 1.0: # Moderate jitter
            f, pxx = signal.periodogram(intervals)
            if len(pxx) > 0 and np.max(pxx) > 5 * np.mean(pxx): # Strong peak
                is_periodic = True
                
        if is_periodic:
            alert_key = f"alert_cooldown:c2:{src_ip}:{dst_ip}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 600, 1) # 10 min cooldown
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    threat_class=ThreatClass.C2_BEACONING,
                    confidence=max(0.4, 0.9 - (cov * 0.5)),
                    evidence={
                        "mean_interval_sec": round(mean_interval, 2),
                        "cov": round(cov, 3),
                        "samples_evaluated": len(ts_array)
                    }
                )
        return None

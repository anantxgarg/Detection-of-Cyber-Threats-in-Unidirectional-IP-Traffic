from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
import redis

class ReconDetector:
    def __init__(self, redis_client: redis.Redis):
        self.r = redis_client
        self.threshold_ports = 20
        self.window_seconds = 60
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'conn':
            return None
            
        src_ip = event.src_ip
        dst_port = event.dst_port
        
        # Fast fan-out tracking
        port_set_key = f"recon_ports:{src_ip}"
        pipe = self.r.pipeline()
        pipe.sadd(port_set_key, dst_port)
        pipe.expire(port_set_key, self.window_seconds)
        pipe.scard(port_set_key)
        _, _, unique_ports = pipe.execute()
        
        if unique_ports > self.threshold_ports:
            # Prevent alert spam by checking if we recently alerted for this
            alert_key = f"alert_cooldown:recon:{src_ip}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 300, 1) # 5 min cooldown
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=src_ip,
                    dst_ip=None,
                    threat_class=ThreatClass.RECON,
                    confidence=0.85,
                    evidence={
                        "unique_ports_scanned": unique_ports,
                        "window_seconds": self.window_seconds,
                        "trigger_port": dst_port
                    }
                )
        return None

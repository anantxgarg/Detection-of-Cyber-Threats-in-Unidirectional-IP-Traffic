from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
import redis

class DNSTunnelDetector:
    def __init__(self, redis_client: redis.Redis):
        self.r = redis_client
        self.window_seconds = 60
        self.rate_threshold = 50 # Queries per min to same domain
        self.size_threshold = 150 # Unusually large query size
        
    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'dns':
            return None
            
        query = event.data.get('query')
        qtype = event.data.get('qtype_name')
        
        if not query:
            return None
            
        src_ip = event.src_ip
        parts = query.split('.')
        if len(parts) < 2:
            return None
            
        base_domain = f"{parts[-2]}.{parts[-1]}"
        
        is_large = len(query) > self.size_threshold
        is_suspicious_type = qtype in ['TXT', 'NULL']
        
        rate_key = f"dns_tunnel_rate:{src_ip}:{base_domain}"
        pipe = self.r.pipeline()
        pipe.incr(rate_key)
        pipe.expire(rate_key, self.window_seconds)
        results = pipe.execute()
        
        query_count = results[0]
        
        score = 0.0
        evidence = {"domain": base_domain, "query_example": query}
        
        if query_count > self.rate_threshold:
            score += 0.5
            evidence["high_query_rate"] = query_count
            
        if is_large:
            score += 0.4
            evidence["large_query_len"] = len(query)
            
        if is_suspicious_type:
            score += 0.3
            evidence["suspicious_qtype"] = qtype
            
        if score >= 0.7:
            alert_key = f"alert_cooldown:dnstunnel:{src_ip}:{base_domain}"
            if not self.r.get(alert_key):
                self.r.setex(alert_key, 300, 1)
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=src_ip,
                    dst_ip=event.dst_ip,
                    threat_class=ThreatClass.DNS_TUNNELLING,
                    confidence=min(0.95, score),
                    evidence=evidence
                )
        return None

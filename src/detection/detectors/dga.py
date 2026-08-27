from src.detection.schemas import DetectionResult, ThreatClass
from src.ingestion.schemas import NormalizedEvent
import math
from collections import Counter

class DGADetector:
    def __init__(self):
        # Placeholder for XGBoost model
        self.mock_mode = True
        
    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in Counter(data).values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def analyze(self, event: NormalizedEvent) -> DetectionResult | None:
        if event.log_type != 'dns':
            return None
            
        query = event.data.get('query')
        if not query:
            return None
            
        parts = query.split('.')
        if len(parts) < 2:
            return None
            
        domain_body = parts[-2]
        entropy = self._shannon_entropy(domain_body)
        length = len(domain_body)
        
        # MOCK ML INFERENCE logic
        if self.mock_mode:
            if length > 14 and entropy > 3.8:
                return DetectionResult(
                    timestamp=event.ts,
                    flow_id=event.data.get('uid'),
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    threat_class=ThreatClass.DGA,
                    confidence=0.8,
                    evidence={
                        "query": query,
                        "entropy": round(entropy, 3),
                        "length": length,
                        "model_used": "mock_heuristic"
                    }
                )
        return None

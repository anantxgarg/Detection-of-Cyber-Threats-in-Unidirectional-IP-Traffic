from pydantic import BaseModel, ConfigDict
from typing import Dict, Any, Optional
from enum import Enum

class ThreatClass(str, Enum):
    RECON = "Recon/Scanning"
    C2_BEACONING = "C2 Beaconing"
    DGA = "DGA"
    DNS_TUNNELLING = "DNS Tunnelling"
    DDOS = "SYN-flood-like traffic anomaly"
    EXFILTRATION = "Potential Data Exfiltration / Abnormal Outbound Transfer"
    ENCRYPTED_ANOMALY = "Encrypted-Session Behavioral Anomaly Detection"

class DetectionResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    timestamp: float
    flow_id: Optional[str] = None
    src_ip: str
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    threat_class: ThreatClass
    confidence: float
    evidence: Dict[str, Any]
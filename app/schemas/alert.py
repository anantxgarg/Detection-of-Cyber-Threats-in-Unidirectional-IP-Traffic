from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from src.detection.schemas import ThreatClass


class Alert(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: float
    flow_id: Optional[str] = None
    src_ip: str
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    threat_class: ThreatClass
    confidence: float
    evidence: dict[str, Any]
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Any, Dict, List

class BaseZeekRecord(BaseModel):
    model_config = ConfigDict(extra='allow', populate_by_name=True)
    ts: float
    uid: str
    id_orig_h: str = Field(alias='id.orig_h')
    id_orig_p: int = Field(alias='id.orig_p')
    id_resp_h: str = Field(alias='id.resp_h')
    id_resp_p: int = Field(alias='id.resp_p')

class ConnRecord(BaseZeekRecord):
    proto: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    local_orig: Optional[bool] = None
    local_resp: Optional[bool] = None
    missed_bytes: Optional[int] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = None
    orig_ip_bytes: Optional[int] = None
    resp_pkts: Optional[int] = None
    resp_ip_bytes: Optional[int] = None

class DnsRecord(BaseZeekRecord):
    proto: str
    trans_id: Optional[int] = None
    rtt: Optional[float] = None
    query: Optional[str] = None
    qclass_name: Optional[str] = None
    qtype_name: Optional[str] = None
    rcode_name: Optional[str] = None
    AA: Optional[bool] = None
    TC: Optional[bool] = None
    RD: Optional[bool] = None
    RA: Optional[bool] = None
    Z: Optional[int] = None
    answers: Optional[List[str]] = None
    TTLs: Optional[List[float]] = None
    rejected: Optional[bool] = None

class SslRecord(BaseZeekRecord):
    version: Optional[str] = None
    cipher: Optional[str] = None
    curve: Optional[str] = None
    server_name: Optional[str] = None
    resumed: Optional[bool] = None
    last_alert: Optional[str] = None
    next_protocol: Optional[str] = None
    established: Optional[bool] = None
    ssl_history: Optional[str] = None
    ja4: Optional[str] = None

class NormalizedEvent(BaseModel):
    log_type: str  # e.g., 'conn', 'dns', 'ssl'
    data: Dict[str, Any]
    
    # Common extracted fields for downstream correlation
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

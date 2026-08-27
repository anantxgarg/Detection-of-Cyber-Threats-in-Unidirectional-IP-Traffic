import pytest
from src.ingestion.schemas import ConnRecord, DnsRecord

def test_conn_record_parsing():
    sample_json = {
        "ts": 1501168159.982247,
        "uid": "CHhAvVGS1DHFhMObi",
        "id.orig_h": "192.168.10.14",
        "id.orig_p": 49182,
        "id.resp_h": "205.251.198.81",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 0.053874969482421875,
        "orig_bytes": 1498,
        "resp_bytes": 105,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 12,
        "orig_ip_bytes": 2130,
        "resp_pkts": 10,
        "resp_ip_bytes": 633
    }
    
    record = ConnRecord.model_validate(sample_json)
    assert record.ts == 1501168159.982247
    assert record.id_orig_h == "192.168.10.14"
    assert record.orig_bytes == 1498
    
    # Test export with alias
    dump = record.model_dump(by_alias=True)
    assert dump["id.orig_h"] == "192.168.10.14"


def test_dns_record_parsing():
    sample_json = {
        "ts": 1501168159.982247,
        "uid": "CHhAvVGS1DHFhMObi",
        "id.orig_h": "192.168.10.14",
        "id.orig_p": 49182,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 12345,
        "query": "www.google.com",
        "qclass_name": "C_INTERNET",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": ["142.250.190.36"],
        "TTLs": [300.0],
        "rejected": False
    }
    
    record = DnsRecord.model_validate(sample_json)
    assert record.query == "www.google.com"
    assert record.answers == ["142.250.190.36"]

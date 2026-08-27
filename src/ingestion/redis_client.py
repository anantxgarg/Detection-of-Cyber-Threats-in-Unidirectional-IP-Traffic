import redis
import json
from .schemas import NormalizedEvent

class RedisManager:
    def __init__(self, host='localhost', port=6379, db=0):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.stream_name = "events:live"

    def push_event(self, event: NormalizedEvent):
        payload = {
            "log_type": event.log_type,
            "ts": str(event.ts),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": str(event.src_port),
            "dst_port": str(event.dst_port),
            "data": json.dumps(event.data)
        }
        # Append to stream and cap size
        self.r.xadd(self.stream_name, payload, maxlen=100000)
        self.update_host_state(event)

    def update_host_state(self, event: NormalizedEvent):
        host_key = f"host_state:{event.src_ip}"
        
        pipe = self.r.pipeline()
        
        if event.log_type == 'conn':
            orig_bytes = event.data.get('orig_bytes', 0)
            if orig_bytes is None:
                orig_bytes = 0
            pipe.hincrby(host_key, 'bytes_out', orig_bytes)
            pipe.hincrby(host_key, 'conn_count', 1)
            
            # Track unique destinations using a SET
            dest_key = f"host_dests:{event.src_ip}"
            pipe.sadd(dest_key, event.dst_ip)
            pipe.expire(dest_key, 3600) # 1 hour TTL
            
        elif event.log_type == 'dns':
            pipe.hincrby(host_key, 'dns_query_count', 1)
            
        pipe.expire(host_key, 3600) # Keep host state for 1 hour
        pipe.execute()

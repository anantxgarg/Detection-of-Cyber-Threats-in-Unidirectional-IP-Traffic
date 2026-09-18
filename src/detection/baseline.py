import redis
import numpy as np
from typing import Tuple

class BaselineEngine:
    def __init__(self, host='localhost', port=6379, db=0):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.window_size = 60  # keep last 60 minutes
        self.bucket_interval = 60 # 60 seconds

    def _get_bucket_ts(self, ts: float) -> int:
        return int(ts) // self.bucket_interval

    def update_from_event(self, event):
        """Updates the current minute bucket for the host."""
        # Guarded updates: if an alert is firing, don't poison the baseline
        if self.r.get(f"alerting:{event.src_ip}"):
            return

        ts = event.ts
        bucket_ts = self._get_bucket_ts(ts)
        pipe = self.r.pipeline()
        
        if event.log_type == 'conn':
            orig_bytes = event.data.get('orig_bytes', 0)
            if orig_bytes:
                b_key = f"bucket:{event.src_ip}:bytes_out:{bucket_ts}"
                pipe.incrby(b_key, orig_bytes)
                pipe.expire(b_key, self.bucket_interval * 3)
                
            # Connection count (useful for DDoS)
            c_key = f"bucket:{event.src_ip}:conn_count:{bucket_ts}"
            pipe.incr(c_key)
            pipe.expire(c_key, self.bucket_interval * 3)

            # Half open count
            conn_state = event.data.get('conn_state')
            if conn_state == 'S0':
                s0_key = f"bucket:{event.src_ip}:half_open:{bucket_ts}"
                pipe.incr(s0_key)
                pipe.expire(s0_key, self.bucket_interval * 3)
                
            hll_key = f"bucket:{event.src_ip}:unique_dests:{bucket_ts}"
            pipe.pfadd(hll_key, event.dst_ip)
            pipe.expire(hll_key, self.bucket_interval * 3)
            
        elif event.log_type == 'dns':
            b_key = f"bucket:{event.src_ip}:dns_count:{bucket_ts}"
            pipe.incr(b_key)
            pipe.expire(b_key, self.bucket_interval * 3)
            
        pipe.execute()

    def finalize_bucket(self, src_ip: str, bucket_ts: int):
        """Called to move a finalized bucket into the rolling history list."""
        pipe = self.r.pipeline()
        
        metrics = ['bytes_out', 'dns_count', 'conn_count', 'half_open']
        for metric in metrics:
            b_key = f"bucket:{src_ip}:{metric}:{bucket_ts}"
            val = self.r.get(b_key) or 0
            h_key = f"history:{src_ip}:{metric}"
            pipe.lpush(h_key, int(val))
            pipe.ltrim(h_key, 0, self.window_size - 1)
        
        # Unique Dests (HyperLogLog)
        hll_key = f"bucket:{src_ip}:unique_dests:{bucket_ts}"
        val = self.r.pfcount(hll_key)
        h_key_dests = f"history:{src_ip}:unique_dests"
        pipe.lpush(h_key_dests, val)
        pipe.ltrim(h_key_dests, 0, self.window_size - 1)
        
        pipe.execute()

    def get_baseline(self, src_ip: str, metric: str) -> Tuple[float, float]:
        """Returns (median, MAD) for the given metric."""
        h_key = f"history:{src_ip}:{metric}"
        samples = self.r.lrange(h_key, 0, -1)
        if not samples:
            return 0.0, 1.0 # default MAD=1.0 to avoid zero division
            
        vals = np.array([float(s) for s in samples])
        median = float(np.median(vals))
        mad = float(np.median(np.abs(vals - median)))
        
        if mad == 0:
            mad = 1.0
            
        return median, mad
